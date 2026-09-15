use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use crate::corpus::{Entry, Provenance, SOURCE_IN_HOUSE, build_entry, sort_entries};
use crate::error::GeneratorResult;
use crate::forward::{Family, Obfuscation, obfuscate};
use crate::term::{Term, Width};

pub const IN_HOUSE_GENERATOR: &str = "disrobe-evidence-mba forward rewriter";
pub const MAX_JOBS: usize = 16;

#[derive(Debug, Clone)]
pub struct Kernel {
    pub name: &'static str,
    pub term: Term,
}

const fn v(index: u32) -> Term {
    Term::var(index)
}

#[must_use]
pub fn kernels() -> Vec<Kernel> {
    vec![
        Kernel {
            name: "not",
            term: Term::not(v(0)),
        },
        Kernel {
            name: "neg",
            term: Term::neg(v(0)),
        },
        Kernel {
            name: "increment",
            term: Term::add(v(0), Term::constant(1)),
        },
        Kernel {
            name: "add",
            term: Term::add(v(0), v(1)),
        },
        Kernel {
            name: "sub",
            term: Term::sub(v(0), v(1)),
        },
        Kernel {
            name: "xor",
            term: Term::xor(v(0), v(1)),
        },
        Kernel {
            name: "and",
            term: Term::and(v(0), v(1)),
        },
        Kernel {
            name: "or",
            term: Term::or(v(0), v(1)),
        },
        Kernel {
            name: "mul",
            term: Term::mul(v(0), v(1)),
        },
        Kernel {
            name: "affine",
            term: Term::add(
                Term::mul(Term::constant(2), v(0)),
                Term::mul(Term::constant(3), v(1)),
            ),
        },
        Kernel {
            name: "andnot",
            term: Term::and(v(0), Term::not(v(1))),
        },
        Kernel {
            name: "nor",
            term: Term::not(Term::or(v(0), v(1))),
        },
        Kernel {
            name: "add3",
            term: Term::add(Term::add(v(0), v(1)), v(2)),
        },
        Kernel {
            name: "xor3",
            term: Term::xor(Term::xor(v(0), v(1)), v(2)),
        },
        Kernel {
            name: "andor3",
            term: Term::or(Term::and(v(0), v(1)), v(2)),
        },
        Kernel {
            name: "mix4",
            term: Term::xor(Term::add(v(0), v(1)), Term::and(v(2), v(3))),
        },
        Kernel {
            name: "sum8",
            term: (1..8).fold(v(0), |accumulated: Term, index: u32| {
                Term::add(accumulated, v(index))
            }),
        },
        Kernel {
            name: "bitmix8",
            term: Term::add(
                Term::or(Term::and(v(0), v(1)), Term::xor(v(2), v(3))),
                Term::and(Term::or(v(4), v(5)), Term::xor(v(6), v(7))),
            ),
        },
    ]
}

const LINEAR_WIDTHS: [Width; 6] = [
    Width::W2,
    Width::W4,
    Width::W8,
    Width::W16,
    Width::W32,
    Width::W64,
];
const HIGHER_WIDTHS: [Width; 3] = [Width::W8, Width::W32, Width::W64];

#[derive(Debug, Clone)]
struct PlanItem {
    kernel_index: usize,
    family: Family,
    width: Width,
}

fn plan() -> Vec<PlanItem> {
    let count: usize = kernels().len();
    let mut items: Vec<PlanItem> = Vec::new();
    for kernel_index in 0..count {
        for family in Family::ALL {
            let widths: &[Width] = match family {
                Family::Linear => &LINEAR_WIDTHS,
                Family::Polynomial | Family::Mixed => &HIGHER_WIDTHS,
            };
            for width in widths {
                items.push(PlanItem {
                    kernel_index,
                    family,
                    width: *width,
                });
            }
        }
    }
    items
}

fn item_seed(item: &PlanItem) -> u64 {
    let family_slot: u64 = match item.family {
        Family::Linear => 1,
        Family::Polynomial => 2,
        Family::Mixed => 3,
    };
    0x5EED_1B0A_0000_0000
        ^ ((item.kernel_index as u64) << 24)
        ^ (family_slot << 16)
        ^ u64::from(item.width.bits())
}

fn build_item(item: &PlanItem, kernels: &[Kernel]) -> GeneratorResult<Option<Entry>> {
    let Some(kernel) = kernels.get(item.kernel_index) else {
        return Ok(None);
    };
    let var_count: u32 = kernel.term.var_count();
    let seed: u64 = item_seed(item);
    let Some(result): Option<Obfuscation> =
        obfuscate(&kernel.term, item.family, item.width, seed, var_count)
    else {
        return Ok(None);
    };
    let id: String = format!(
        "inhouse-{}-{}-w{}",
        item.family.label(),
        kernel.name,
        item.width.bits()
    );
    let provenance: Provenance<'_> = Provenance {
        source: SOURCE_IN_HOUSE,
        generator: IN_HOUSE_GENERATOR,
        transform: item.family.label(),
        seed,
    };
    build_entry(
        &id,
        provenance,
        &kernel.term,
        &result.obfuscated,
        item.width,
    )
    .map(Some)
}

type Batch = GeneratorResult<Vec<(usize, Entry)>>;

pub fn generate_in_house(jobs: usize) -> GeneratorResult<Vec<Entry>> {
    let items: Vec<PlanItem> = plan();
    let kernel_set: Vec<Kernel> = kernels();
    let workers: usize = jobs.clamp(1, MAX_JOBS).min(items.len().max(1));
    let cursor: AtomicUsize = AtomicUsize::new(0);
    let mut collected: Vec<(usize, Entry)> = Vec::with_capacity(items.len());

    let harvested: Vec<Batch> = thread::scope(|scope: &thread::Scope<'_, '_>| {
        let handles: Vec<thread::ScopedJoinHandle<'_, Batch>> = (0..workers)
            .map(|_| {
                let cursor: &AtomicUsize = &cursor;
                let items: &Vec<PlanItem> = &items;
                let kernel_set: &Vec<Kernel> = &kernel_set;
                scope.spawn(move || -> Batch {
                    let mut local: Vec<(usize, Entry)> = Vec::new();
                    loop {
                        let index: usize = cursor.fetch_add(1, Ordering::Relaxed);
                        let Some(item) = items.get(index) else {
                            break;
                        };
                        if let Some(entry) = build_item(item, kernel_set)? {
                            local.push((index, entry));
                        }
                    }
                    Ok(local)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle: thread::ScopedJoinHandle<'_, Batch>| {
                handle.join().unwrap_or_else(|_| Ok(Vec::new()))
            })
            .collect()
    });

    for batch in harvested {
        collected.extend(batch?);
    }
    collected.sort_by_key(|(index, _): &(usize, Entry)| *index);
    let mut entries: Vec<Entry> = collected
        .into_iter()
        .map(|(_, entry): (usize, Entry)| entry)
        .collect();
    sort_entries(&mut entries);
    Ok(entries)
}
