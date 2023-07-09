use std::{
    mem::MaybeUninit,
    sync::{Arc, LazyLock},
};

use parking_lot::Mutex;

use crate::{
    core::{Collector, Desc, Describer, Metric, MetricVec, MetricVecBuilder},
    proto::{self, LabelPair},
    value::make_label_pairs,
    Opts,
};

const E_10_MIN: i64 = -9;
const E_10_MAX: i64 = 18;
const BUCKETS_PER_DECIMAL: usize = 18;
const DECIMAL_BUCKETS_COUNT: usize = (E_10_MAX - E_10_MIN) as usize;
const BUCKETS_COUNT: usize = DECIMAL_BUCKETS_COUNT * BUCKETS_PER_DECIMAL;
static BUCKET_MULTIPLIER: LazyLock<f64> =
    LazyLock::new(|| 10f64.powf(1.0f64 / BUCKETS_PER_DECIMAL as f64));
static LOWER_BUCKET_RANGE: LazyLock<String> =
    LazyLock::new(|| format!("0...{:.3e}", 10f64.powi(E_10_MIN as i32)));
static UPPER_BUCKET_RANGE: LazyLock<String> =
    LazyLock::new(|| format!("{:.3e}...+Inf", 10f64.powi(E_10_MAX as i32)));
static BUCKET_RANGES: LazyLock<[String; BUCKETS_COUNT]> = LazyLock::new(|| {
    // SAFETY: The `assume_init` is safe because the type we are claiming to
    // have initialized here is a bunch of `MaybeUninit`s, which do not require
    // initialization.
    let mut ranges: [MaybeUninit<String>; BUCKETS_COUNT] =
        unsafe { MaybeUninit::uninit().assume_init() };
    let mut v = 10f64.powi(E_10_MIN as i32);
    let mut start = format!("{:.3e}", v);
    for elem in &mut ranges {
        v = v * *BUCKET_MULTIPLIER;
        let end = format!("{:.3e}", v);
        elem.write(format!("{}...{}", start, end));
        start = end;
    }
    // SAFETY: We've iterated over the full array and initialized every element with
    // a `String`.
    unsafe { std::mem::transmute(ranges) }
});

#[derive(Default)]
struct Inner {
    decimal_buckets: [Option<[u64; BUCKETS_PER_DECIMAL as usize]>; DECIMAL_BUCKETS_COUNT as usize],
    lower: u64,
    upper: u64,
    sum: f64,
}

#[allow(missing_debug_implementations)]
#[derive(Clone)]
pub struct VMHistogram {
    inner: Arc<Mutex<Inner>>,
    desc: Arc<Desc>,
    label_pairs: Arc<Vec<LabelPair>>,
}

impl VMHistogram {
    pub fn with_opts(opts: &Opts) -> crate::Result<Self> {
        VMHistogram::with_opts_and_label_values(opts, &[])
    }

    pub fn with_opts_and_label_values(opts: &Opts, label_values: &[&str]) -> crate::Result<Self> {
        let desc = opts.describe()?;

        let label_pairs = make_label_pairs(&desc, label_values)?;
        Ok(VMHistogram {
            inner: Arc::new(Mutex::new(Inner::default())),
            desc: Arc::new(desc),
            label_pairs: Arc::new(label_pairs),
        })
    }

    pub fn observe(&self, value: f64) {
        if value.is_nan() || value.is_sign_negative() {
            return;
        }
        let bucket_idx = (value.log10() - E_10_MIN as f64) * BUCKETS_PER_DECIMAL as f64;
        let mut inner = self.inner.lock();
        inner.sum += value;
        if bucket_idx.is_sign_negative() {
            inner.lower += 1;
        } else if bucket_idx as usize >= BUCKETS_COUNT {
            inner.upper += 1;
        } else {
            let mut idx = bucket_idx as usize;
            if idx as f64 == bucket_idx && idx > 0 {
                // Edge case for 10^n values, which must go to the lower bucket
                // according to Prometheus logic for `le`-based histograms.
                idx = idx - 1;
            }
            let decimal_bucket_idx = idx / BUCKETS_PER_DECIMAL;
            let offset = idx % BUCKETS_PER_DECIMAL;
            let bucket = &mut inner.decimal_buckets[decimal_bucket_idx];
            bucket.get_or_insert_with(Default::default)[offset] += 1;
        }
    }

    fn proto(&self) -> proto::VMHistogram {
        let mut h = proto::VMHistogram::default();
        let mut count_total = 0;

        let inner = self.inner.lock();
        let sum_total = inner.sum;
        inner.visit_nonzero_buckets(|vmrange, count| {
            let mut range_proto = proto::VMRange::default();
            range_proto.set_range(vmrange.to_owned());
            range_proto.set_count(count);
            h.mut_ranges().push(range_proto);
            count_total += count;
        });
        h.set_sample_count(count_total);
        h.set_sample_sum(sum_total);
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

pub type VMHistogramVec = MetricVec<VMHistogramVecBuilder>;

impl VMHistogramVec {
    #[allow(missing_docs)]
    pub fn new(opts: Opts, label_names: &[&str]) -> crate::Result<VMHistogramVec> {
        let variable_names = label_names.iter().map(|s| (*s).to_owned()).collect();
        let opts = opts.variable_labels(variable_names);
        let metric_vec =
            MetricVec::create(proto::MetricType::HISTOGRAM, VMHistogramVecBuilder {}, opts)?;

        Ok(metric_vec)
    }
}

impl Inner {
    pub fn visit_nonzero_buckets<F>(&self, mut visitor: F)
    where
        F: FnMut(&str, u64),
    {
        if self.lower > 0 {
            visitor(&LOWER_BUCKET_RANGE, self.lower);
        }
        for (decimal_bucket_idx, bucket) in self.decimal_buckets.iter().enumerate() {
            if let Some(buckets) = bucket {
                for (offset, count) in buckets.iter().enumerate() {
                    if *count > 0 {
                        let bucket_idx = decimal_bucket_idx * BUCKETS_PER_DECIMAL + offset;
                        let vmrange = BUCKET_RANGES[bucket_idx].as_str();
                        visitor(vmrange, *count);
                    }
                }
            }
        }
        if self.upper > 0 {
            visitor(&UPPER_BUCKET_RANGE, self.upper)
        }
    }
}
