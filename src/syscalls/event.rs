use noct_descriptor::ResourceDescriptor;

pub fn open(_: usize, _: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    let event_queue = noct_input::EventQueue::new();

    let process = &noct_sched::this_thread().process;

    let mut reslock = process.resources.lock();

    let descr = reslock.make(ResourceDescriptor::EventQueue(event_queue));

    noct_input_dispatcher::register(process.id, descr.id());

    Some(descr.id())
}
