#[must_use]
pub fn scc(adjacency: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let count: usize = adjacency.len();
    let mut indices: Vec<Option<usize>> = vec![None; count];
    let mut lowlink: Vec<usize> = vec![0; count];
    let mut on_stack: Vec<bool> = vec![false; count];
    let mut stack: Vec<usize> = Vec::new();
    let mut result: Vec<Vec<usize>> = Vec::new();
    let mut counter: usize = 0;

    for start in 0..count {
        if indices[start].is_some() {
            continue;
        }
        let mut work: Vec<(usize, usize)> = vec![(start, 0)];
        while let Some(&(node, child)) = work.last() {
            if indices[node].is_none() {
                indices[node] = Some(counter);
                lowlink[node] = counter;
                counter += 1;
                stack.push(node);
                on_stack[node] = true;
            }
            let neighbors: &[usize] = &adjacency[node];
            if child < neighbors.len() {
                if let Some(last) = work.last_mut() {
                    last.1 = child + 1;
                }
                let next: usize = neighbors[child];
                if indices[next].is_none() {
                    work.push((next, 0));
                } else if on_stack[next]
                    && let Some(next_index) = indices[next]
                    && next_index < lowlink[node]
                {
                    lowlink[node] = next_index;
                }
            } else {
                if indices[node] == Some(lowlink[node]) {
                    let mut component: Vec<usize> = Vec::new();
                    while let Some(popped) = stack.pop() {
                        on_stack[popped] = false;
                        component.push(popped);
                        if popped == node {
                            break;
                        }
                    }
                    result.push(component);
                }
                work.pop();
                if let Some(&(parent, _)) = work.last()
                    && lowlink[node] < lowlink[parent]
                {
                    lowlink[parent] = lowlink[node];
                }
            }
        }
    }
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::scc;

    #[test]
    fn leaves_precede_callers_in_reverse_topological_order() {
        let adjacency: Vec<Vec<usize>> = vec![vec![1, 2], vec![], vec![1]];
        let order: Vec<Vec<usize>> = scc(&adjacency);
        let position = |node: usize| -> usize {
            order
                .iter()
                .position(|component: &Vec<usize>| component.contains(&node))
                .unwrap()
        };
        assert!(position(1) < position(0));
        assert!(position(2) < position(0));
    }

    #[test]
    fn collapses_a_cycle_into_one_component() {
        let adjacency: Vec<Vec<usize>> = vec![vec![1], vec![2], vec![0], vec![0]];
        let order: Vec<Vec<usize>> = scc(&adjacency);
        let cycle: &Vec<usize> = order
            .iter()
            .find(|component: &&Vec<usize>| component.len() == 3)
            .unwrap();
        assert!(cycle.contains(&0) && cycle.contains(&1) && cycle.contains(&2));
        assert_eq!(order.iter().map(Vec::len).sum::<usize>(), 4);
    }

    #[test]
    fn self_loop_is_its_own_component() {
        let adjacency: Vec<Vec<usize>> = vec![vec![0]];
        assert_eq!(scc(&adjacency), vec![vec![0]]);
    }
}
