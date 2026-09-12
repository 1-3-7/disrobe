#include "corpus.h"

#define SORT_CAPACITY 72

void insertion_sort(i32 *values, u32 count) {
    for (u32 i = 1; i < count; i++) {
        i32 pivot = values[i];
        u32 j = i;
        while (j > 0 && values[j - 1] > pivot) {
            values[j] = values[j - 1];
            j--;
        }
        values[j] = pivot;
    }
}

static void swap_slots(i32 *values, u32 left, u32 right) {
    i32 carried = values[left];
    values[left] = values[right];
    values[right] = carried;
}

void shell_sort(i32 *values, u32 count) {
    u32 gap = 1;
    while (gap * 3 + 1 < count) {
        gap = gap * 3 + 1;
    }
    while (gap > 0) {
        for (u32 i = gap; i < count; i++) {
            i32 pivot = values[i];
            u32 j = i;
            while (j >= gap && values[j - gap] > pivot) {
                values[j] = values[j - gap];
                j -= gap;
            }
            values[j] = pivot;
        }
        gap /= 3;
    }
}

u32 hoare_partition(i32 *values, u32 low, u32 high) {
    i32 pivot = values[low + (high - low) / 2];
    u32 left = low;
    u32 right = high;
    for (;;) {
        while (values[left] < pivot) {
            left++;
        }
        while (values[right] > pivot) {
            right--;
        }
        if (left >= right) {
            return right;
        }
        swap_slots(values, left, right);
        left++;
        if (right == 0) {
            return 0;
        }
        right--;
    }
}

void quicksort(i32 *values, u32 low, u32 high) {
    if (low >= high) {
        return;
    }
    u32 split = hoare_partition(values, low, high);
    quicksort(values, low, split);
    quicksort(values, split + 1, high);
}

void sift_down(i32 *values, u32 root, u32 count) {
    while (root * 2 + 1 < count) {
        u32 child = root * 2 + 1;
        if (child + 1 < count && values[child] < values[child + 1]) {
            child++;
        }
        if (values[root] >= values[child]) {
            return;
        }
        swap_slots(values, root, child);
        root = child;
    }
}

void heapsort(i32 *values, u32 count) {
    if (count < 2) {
        return;
    }
    for (u32 step = count / 2; step > 0; step--) {
        sift_down(values, step - 1, count);
    }
    for (u32 end = count - 1; end > 0; end--) {
        swap_slots(values, 0, end);
        sift_down(values, 0, end);
    }
}

i32 binary_search(const i32 *values, u32 count, i32 wanted) {
    u32 low = 0;
    u32 high = count;
    while (low < high) {
        u32 middle = low + (high - low) / 2;
        if (values[middle] == wanted) {
            return (i32)middle;
        }
        if (values[middle] < wanted) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    return -((i32)low + 1);
}

u32 merge_runs(i32 *out, const i32 *left, u32 left_count, const i32 *right, u32 right_count) {
    u32 a = 0;
    u32 b = 0;
    u32 written = 0;
    while (a < left_count && b < right_count) {
        out[written++] = left[a] <= right[b] ? left[a++] : right[b++];
    }
    while (a < left_count) {
        out[written++] = left[a++];
    }
    while (b < right_count) {
        out[written++] = right[b++];
    }
    return written;
}

int is_sorted(const i32 *values, u32 count) {
    for (u32 i = 1; i < count; i++) {
        if (values[i - 1] > values[i]) {
            return 0;
        }
    }
    return 1;
}

const char *ordering_report(int sorted, i32 found) {
    if (!sorted) {
        return "the sequence left the sorter still out of order";
    }
    if (found < 0) {
        return "the sorted sequence lost the value the search wanted";
    }
    return "the sequence sorted and the search found its target";
}

u64 corpus_main(u64 seed) {
    i32 first[SORT_CAPACITY];
    i32 second[SORT_CAPACITY];
    i32 third[SORT_CAPACITY];
    i32 merged[SORT_CAPACITY * 2];

    for (u32 i = 0; i < SORT_CAPACITY; i++) {
        first[i] = (i32)((seed * 6364136223846793005ull + i * 1442695040888963407ull) >> 40);
        second[i] = (i32)((seed * 2862933555777941757ull + i * 3037000493ull) >> 42);
        third[i] = first[i] ^ second[i];
    }

    insertion_sort(first, SORT_CAPACITY);
    quicksort(second, 0, SORT_CAPACITY - 1);
    shell_sort(third, SORT_CAPACITY);
    heapsort(first, SORT_CAPACITY);
    u32 total_merged = merge_runs(merged, first, SORT_CAPACITY, second, SORT_CAPACITY);
    int sorted = is_sorted(merged, total_merged) & is_sorted(third, SORT_CAPACITY);
    i32 found = binary_search(first, SORT_CAPACITY, first[SORT_CAPACITY / 2]);
    const char *report = ordering_report(sorted, found);

    u64 total = (u64)total_merged * 97u + (u64)(found + 1) * 89u + (u64)sorted;
    for (u32 i = 0; i < total_merged; i++) {
        total = total * 131u + (u64)(u32)merged[i];
    }
    for (const char *p = report; *p != 0; p++) {
        total ^= (u64)(u8)*p << 3;
    }
    return total;
}
