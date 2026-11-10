//! Bounded, incremental transfer of background analysis samples.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;

use crate::types::{BackgroundTask, COMPLEXITY_SAMPLE_INTERVAL, RCMSE_SAMPLE_INTERVAL};
use crate::analysis::{calculate_kolmogorov_complexity, calculate_rcmse_quick};

const BATCH_SIZE: usize = 16_384;

#[derive(Clone, Copy)]
pub enum AnalysisTask {
    Complexity,
    Rcmse,
}

/// Produces each sample once and transfers ownership of each batch once.
/// Transfer time/space is O(samples), rather than cloning O(samples^2 / batch).
pub fn compute_samples(
    data: &[u8],
    task: AnalysisTask,
    sender: &SyncSender<BackgroundTask>,
    cancelled: &AtomicBool,
) {
    let (interval, window) = match task {
        AnalysisTask::Complexity => (COMPLEXITY_SAMPLE_INTERVAL, 128),
        AnalysisTask::Rcmse => (RCMSE_SAMPLE_INTERVAL, 256),
    };
    let samples = data.len().div_ceil(interval);
    for first in (0..samples).step_by(BATCH_SIZE) {
        let end = (first + BATCH_SIZE).min(samples);
        let mut batch = Vec::with_capacity(end - first);
        for i in first..end {
            if cancelled.load(Ordering::Relaxed) {
                return;
            }
            let start = i * interval;
            let bytes = &data[start..start.saturating_add(window).min(data.len())];
            batch.push(match task {
                AnalysisTask::Complexity => calculate_kolmogorov_complexity(bytes) as f32,
                AnalysisTask::Rcmse => calculate_rcmse_quick(bytes),
            });
        }
        let progress = end as f32 / samples as f32;
        let update = match task {
            AnalysisTask::Complexity => BackgroundTask::ComplexityPartial {
                data: batch,
                progress,
            },
            AnalysisTask::Rcmse => BackgroundTask::RcmsePartial {
                data: batch,
                progress,
            },
        };
        if sender.send(update).is_err() {
            return;
        }
    }
    let _ = sender.send(match task {
        AnalysisTask::Complexity => BackgroundTask::ComplexityComplete,
        AnalysisTask::Rcmse => BackgroundTask::RcmseComplete,
    });
}

#[cfg(test)]
mod tests {
    use crate::types::BackgroundTasks;
    use super::*;

    #[test]
    fn two_workers_share_channel_and_deliver_partial_tail() {
        let tasks = BackgroundTasks::new();
        let data: Vec<u8> = (0..129).map(|i| i as u8).collect();
        compute_samples(
            &data,
            AnalysisTask::Complexity,
            &tasks.sender,
            &tasks.cancelled,
        );
        compute_samples(&data, AnalysisTask::Rcmse, &tasks.sender, &tasks.cancelled);
        let mut complexity = Vec::new();
        let mut rcmse = Vec::new();
        let mut completions = 0;
        for update in tasks.receiver.try_iter() {
            match update {
                BackgroundTask::ComplexityPartial { data, progress } => {
                    complexity.extend(data);
                    assert_eq!(progress, 1.0);
                }
                BackgroundTask::RcmsePartial { data, progress } => {
                    rcmse.extend(data);
                    assert_eq!(progress, 1.0);
                }
                _ => completions += 1,
            }
        }
        assert_eq!(completions, 2);
        assert_eq!(complexity.len(), 3);
        assert_eq!(rcmse.len(), 3);
        for (i, (&c, &r)) in complexity.iter().zip(&rcmse).enumerate() {
            let start = i * 64;
            assert_eq!(
                c,
                calculate_kolmogorov_complexity(&data[start..(start + 128).min(data.len())]) as f32
            );
            assert_eq!(
                r,
                calculate_rcmse_quick(&data[start..(start + 256).min(data.len())])
            );
        }
    }

    #[test]
    fn batches_do_not_retransmit_previous_samples() {
        let tasks = BackgroundTasks::new();
        let data = vec![0; (BATCH_SIZE + 1) * 64];
        compute_samples(
            &data,
            AnalysisTask::Complexity,
            &tasks.sender,
            &tasks.cancelled,
        );
        let lengths: Vec<_> = tasks
            .receiver
            .try_iter()
            .filter_map(|message| match message {
                BackgroundTask::ComplexityPartial { data, .. } => Some(data.len()),
                _ => None,
            })
            .collect();
        assert_eq!(lengths, [BATCH_SIZE, 1]);
    }

    #[test]
    fn cancellation_stops_work_without_publishing() {
        let tasks = BackgroundTasks::new();
        tasks.cancelled.store(true, Ordering::Relaxed);
        compute_samples(
            &[0; 128],
            AnalysisTask::Complexity,
            &tasks.sender,
            &tasks.cancelled,
        );
        assert!(tasks.receiver.try_recv().is_err());
    }
}
