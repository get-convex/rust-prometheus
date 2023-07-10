//! Rust reimplementation of https://github.com/VictoriaMetrics/metrics/blob/ae1e9d8058de94e5622ccee515ece7992d67d209/histogram.go
// Originally distributed under the following license:
// The MIT License (MIT)
//
// Copyright (c) 2019 VictoriaMetrics
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use std::sync::Arc;

use lazy_static::lazy_static;
use parking_lot::RwLock;

use crate::{
    core::{
        Atomic, AtomicF64, AtomicU64, Collector, Desc, Describer, Metric, MetricVec,
        MetricVecBuilder,
    },
    proto::{self, LabelPair},
    value::make_label_pairs,
    Opts,
};

const E_10_MIN: i32 = -9;
const E_10_MAX: i32 = 18;
const BUCKETS_PER_DECIMAL: usize = 18;
const DECIMAL_BUCKETS_COUNT: usize = (E_10_MAX - E_10_MIN) as usize;
const BUCKETS_COUNT: usize = DECIMAL_BUCKETS_COUNT * BUCKETS_PER_DECIMAL;
lazy_static! {
    static ref BUCKET_MULTIPLIER: f64 = 10f64.powf(1.0f64 / BUCKETS_PER_DECIMAL as f64);
    static ref LOWER_BUCKET_RANGE: String = format!("0...{:.3e}", 10f64.powi(E_10_MIN));
    static ref UPPER_BUCKET_RANGE: String = format!("{:.3e}...+Inf", 10f64.powi(E_10_MAX));
    static ref BUCKET_RANGES: Vec<String> = {
        let mut ranges: Vec<String> = vec![String::new(); BUCKETS_COUNT];
        let mut v = 10f64.powi(E_10_MIN);
        let mut start = format!("{:.3e}", v);
        for elem in &mut ranges {
            v *= *BUCKET_MULTIPLIER;
            let end = format!("{:.3e}", v);
            *elem = format!("{}...{}", start, end);
            start = end;
        }
        ranges
    };
}

#[derive(Default)]
struct Inner {
    decimal_buckets: [[AtomicU64; BUCKETS_PER_DECIMAL]; DECIMAL_BUCKETS_COUNT],
    lower: AtomicU64,
    upper: AtomicU64,
    sum: AtomicF64,
}

/// Histogram is a histogram for non-negative values with automatically created buckets.
///
/// See https://medium.com/@valyala/improving-histogram-usability-for-prometheus-and-grafana-bc7e5df0e350
///
/// Each bucket contains a counter for values in the given range.
/// Each non-empty bucket is exposed via the following metric:
///
/// <metric_name>_bucket{<optional_tags>,vmrange="<start>...<end>"} <counter>
///
/// Where:
///
///   - <metric_name> is the metric name passed to NewHistogram
///   - <optional_tags> is optional tags for the <metric_name>, which are passed to NewHistogram
///   - <start> and <end> - start and end values for the given bucket
///   - <counter> - the number of hits to the given bucket during Update* calls
///
/// Histogram buckets can be converted to Prometheus-like buckets with `le` labels
/// with `prometheus_buckets(<metric_name>_bucket)` function from PromQL extensions in VictoriaMetrics.
/// (see https://github.com/VictoriaMetrics/VictoriaMetrics/wiki/MetricsQL ):
///
/// prometheus_buckets(request_duration_bucket)
///
/// Time series produced by the Histogram have better compression ratio comparing to
/// Prometheus histogram buckets with `le` labels, since they don't include counters
/// for all the previous buckets.
///
/// Zero histogram is usable.
#[allow(missing_debug_implementations)]
#[derive(Clone)]
pub struct VMHistogram {
    inner: Arc<RwLock<Inner>>,
    desc: Arc<Desc>,
    label_pairs: Arc<Vec<LabelPair>>,
}

impl VMHistogram {
    /// `with_opts` creates a [`VMHistogram`] with the `opts` options.
    pub fn with_opts(opts: Opts) -> crate::Result<Self> {
        VMHistogram::with_opts_and_label_values(&opts, &[])
    }

    fn with_opts_and_label_values(opts: &Opts, label_values: &[&str]) -> crate::Result<Self> {
        let desc = opts.describe()?;

        let label_pairs = make_label_pairs(&desc, label_values)?;
        Ok(VMHistogram {
            inner: Default::default(),
            desc: Arc::new(desc),
            label_pairs: Arc::new(label_pairs),
        })
    }

    /// Add a single observation to the [`VMHistogram`]
    /// Negative values and NaNs are ignored.
    pub fn observe(&self, value: f64) {
        if value.is_nan() || value.is_sign_negative() {
            return;
        }
        let bucket_idx = (value.log10() - E_10_MIN as f64) * BUCKETS_PER_DECIMAL as f64;
        let inner = self.inner.read();
        inner.sum.inc_by(value);
        if bucket_idx.is_sign_negative() {
            inner.lower.inc_by(1);
        } else if bucket_idx as usize >= BUCKETS_COUNT {
            inner.upper.inc_by(1);
        } else {
            let mut idx = bucket_idx as usize;
            if idx as f64 == bucket_idx && idx > 0 {
                // Edge case for 10^n values, which must go to the lower bucket
                // according to Prometheus logic for `le`-based histograms.
                idx -= 1;
            }
            let decimal_bucket_idx = idx / BUCKETS_PER_DECIMAL;
            let offset = idx % BUCKETS_PER_DECIMAL;
            let bucket = &inner.decimal_buckets[decimal_bucket_idx];
            bucket[offset].inc_by(1);
        }
    }

    fn proto(&self) -> proto::VMHistogram {
        let mut h = proto::VMHistogram::default();
        let mut count_total = 0;

        let inner = self.inner.write();
        inner.visit_nonzero_buckets(|vmrange, count| {
            let mut range_proto = proto::VMRange::default();
            range_proto.set_range(vmrange.to_owned());
            range_proto.set_count(count);
            h.mut_ranges().push(range_proto);
            count_total += count;
        });
        h.set_sample_count(count_total);
        h.set_sample_sum(inner.sum.get());
        h
    }
}

#[derive(Clone, Debug)]
pub struct VMHistogramVecBuilder {}

impl MetricVecBuilder for VMHistogramVecBuilder {
    type M = VMHistogram;
    type P = Opts;

    fn build(&self, opts: &Self::P, vals: &[&str]) -> crate::Result<Self::M> {
        VMHistogram::with_opts_and_label_values(opts, vals)
    }
}

impl Metric for VMHistogram {
    fn metric(&self) -> crate::proto::Metric {
        let mut m = proto::Metric::default();
        m.set_label((*self.label_pairs).clone().into());

        let h = self.proto();
        m.set_vm_histogram(h);
        m
    }
}

impl Collector for VMHistogram {
    fn desc(&self) -> Vec<&Desc> {
        vec![&self.desc]
    }

    fn collect(&self) -> Vec<proto::MetricFamily> {
        let mut m = proto::MetricFamily::default();
        m.set_name(self.desc.fq_name.clone());
        m.set_help(self.desc.help.clone());
        m.set_field_type(proto::MetricType::VMHISTOGRAM);
        m.set_metric(vec![self.metric()].into());
        vec![m]
    }
}

/// A [`Collector`] that bundles a set of VMHistograms that all share the
/// same [`Desc`], but have different values for their variable labels. This is used
/// if you want to count the same thing partitioned by various dimensions
/// (e.g. HTTP request latencies, partitioned by status code and method).
pub type VMHistogramVec = MetricVec<VMHistogramVecBuilder>;

impl VMHistogramVec {
    /// Create a new [`VMHistogramVec`] based on the provided
    /// [`Opts`] and partitioned by the given label names. At least
    /// one label name must be provided.
    pub fn new(opts: Opts, label_names: &[&str]) -> crate::Result<VMHistogramVec> {
        let variable_names = label_names.iter().map(|s| (*s).to_owned()).collect();
        let opts = opts.variable_labels(variable_names);
        let metric_vec = MetricVec::create(
            proto::MetricType::VMHISTOGRAM,
            VMHistogramVecBuilder {},
            opts,
        )?;

        Ok(metric_vec)
    }
}

impl Inner {
    /// `visit_nonzero_buckets` calls `visitor` for all buckets with non-zero counters.
    ///
    /// vmrange contains "<start>...<end>" string with bucket bounds. The lower bound
    /// isn't included in the bucket, while the upper bound is included.
    /// This is required to be compatible with Prometheus-style histogram buckets
    /// with `le` (less or equal) labels.
    fn visit_nonzero_buckets<F>(&self, mut visitor: F)
    where
        F: FnMut(&str, u64),
    {
        if self.lower.get() > 0 {
            visitor(&LOWER_BUCKET_RANGE, self.lower.get());
        }
        for (decimal_bucket_idx, decimal_bucket) in self.decimal_buckets.iter().enumerate() {
            for (offset, count) in decimal_bucket.iter().enumerate() {
                if count.get() > 0 {
                    let bucket_idx = decimal_bucket_idx * BUCKETS_PER_DECIMAL + offset;
                    let vmrange = BUCKET_RANGES[bucket_idx].as_str();
                    visitor(vmrange, count.get());
                }
            }
        }
        if self.upper.get() > 0 {
            visitor(&UPPER_BUCKET_RANGE, self.upper.get())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::f64::EPSILON;

    use crate::{core::Collector, Error, Opts, VMHistogram, VMHistogramVec};

    #[test]
    fn test_vmhistogram() {
        let opts = Opts::new("test1", "test help")
            .const_label("a", "1")
            .const_label("b", "2");
        let histogram = VMHistogram::with_opts(opts).unwrap();
        histogram.observe(1.0);
        histogram.observe(3.0);
        histogram.observe(5.0);

        let mut mfs = histogram.collect();
        assert_eq!(mfs.len(), 1);

        let mf = mfs.pop().unwrap();
        let m = mf.get_metric().get(0).unwrap();
        assert_eq!(m.get_label().len(), 2);
        let proto_histogram = m.get_vm_histogram();
        assert_eq!(proto_histogram.get_sample_count(), 3);
        assert!(9.0 - proto_histogram.get_sample_sum() < EPSILON);
    }

    #[test]
    fn test_vmhistogram_vec_with_label_values() {
        let vec = VMHistogramVec::new(
            Opts::new("test_histogram_vec", "test histogram vec help"),
            &["l1", "l2"],
        )
        .unwrap();

        assert!(vec.remove_label_values(&["v1", "v2"]).is_err());
        vec.with_label_values(&["v1", "v2"]).observe(1.0);
        assert!(vec.remove_label_values(&["v1", "v2"]).is_ok());

        assert!(vec.remove_label_values(&["v1"]).is_err());
        assert!(vec.remove_label_values(&["v1", "v3"]).is_err());
    }

    #[test]
    fn test_error_on_inconsistent_label_cardinality() {
        let hist = VMHistogram::with_opts(
            opts!("example_histogram", "Used as an example",).variable_label("example_variable"),
        );

        if let Err(Error::InconsistentCardinality { expect, got }) = hist {
            assert_eq!(1, expect);
            assert_eq!(0, got);
        } else {
            panic!("Expected InconsistentCardinality error.")
        }
    }
}
