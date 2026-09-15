use std::sync::Mutex;

pub trait Progress: Send + Sync + std::fmt::Debug {
    fn set_total(&self, total: u64);
    fn set_pos(&self, pos: u64);
    fn tick(&self);
    fn set_message(&self, message: &str);
    fn finish(&self, message: &str);
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NoopProgress;

impl Progress for NoopProgress {
    #[inline]
    fn set_total(&self, _total: u64) {}
    #[inline]
    fn set_pos(&self, _pos: u64) {}
    #[inline]
    fn tick(&self) {}
    #[inline]
    fn set_message(&self, _message: &str) {}
    #[inline]
    fn finish(&self, _message: &str) {}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgressEvent {
    SetTotal(u64),
    SetPos(u64),
    Tick,
    SetMessage(String),
    Finish(String),
}

#[derive(Debug, Default)]
pub struct CapturingProgress {
    events: Mutex<Vec<ProgressEvent>>,
}

impl CapturingProgress {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> Vec<ProgressEvent> {
        self.events.lock().map_or_else(
            |_| Vec::new(),
            |g: std::sync::MutexGuard<'_, Vec<ProgressEvent>>| g.clone(),
        )
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.events.lock().map_or(0, |g| g.len())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn push(&self, event: ProgressEvent) {
        if let Ok(mut g) = self.events.lock() {
            g.push(event);
        }
    }
}

impl Progress for CapturingProgress {
    fn set_total(&self, total: u64) {
        self.push(ProgressEvent::SetTotal(total));
    }
    fn set_pos(&self, pos: u64) {
        self.push(ProgressEvent::SetPos(pos));
    }
    fn tick(&self) {
        self.push(ProgressEvent::Tick);
    }
    fn set_message(&self, message: &str) {
        self.push(ProgressEvent::SetMessage(message.to_owned()));
    }
    fn finish(&self, message: &str) {
        self.push(ProgressEvent::Finish(message.to_owned()));
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn noop_swallows_all_calls() {
        let p: NoopProgress = NoopProgress;
        p.set_total(100);
        p.set_pos(50);
        p.tick();
        p.set_message("hi");
        p.finish("done");
    }

    #[test]
    fn capturing_records_in_order() {
        let p: CapturingProgress = CapturingProgress::new();
        p.set_total(3);
        p.tick();
        p.tick();
        p.set_pos(2);
        p.finish("done");
        let snap: Vec<ProgressEvent> = p.snapshot();
        assert_eq!(snap.len(), 5);
        assert_eq!(snap[0], ProgressEvent::SetTotal(3));
        assert_eq!(snap[1], ProgressEvent::Tick);
        assert_eq!(snap[2], ProgressEvent::Tick);
        assert_eq!(snap[3], ProgressEvent::SetPos(2));
        assert_eq!(snap[4], ProgressEvent::Finish("done".to_owned()));
    }

    #[test]
    fn capturing_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CapturingProgress>();
        assert_send_sync::<NoopProgress>();
    }
}
