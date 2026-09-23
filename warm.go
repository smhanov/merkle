package merkle

import (
	"io"
	"runtime"
	"sync"
)

// Warm precomputes the hash of every node in the index, in parallel.
// It reads the file sequentially in large blocks and hashes leaves on
// all cores, then builds the upper levels bottom-up from the memo
// alone. A cold Root walks the tree lazily and serially, so on a
// large file callers that expect to touch every node should call Warm
// first; Root and all hashNode calls afterwards are memo hits. Warm
// is a no-op when the root is already memoized.
func (ix *Index) Warm() error {
	if ix.size == 0 {
		return nil
	}
	top := len(ix.levels) - 1
	var root Hash
	if _, err := ix.memo.ReadAt(root[:], ix.levels[top].off); err != nil {
		return err
	}
	if root != (Hash{}) {
		return nil
	}
	if err := ix.warmLeaves(); err != nil {
		return err
	}
	return ix.warmInternal()
}

const (
	warmReadBlock = 4 << 20 // bytes per sequential read, a multiple of chunkSize
	warmBatch     = 256     // leaf hashes per memo WriteAt
)

// warmLeaves hashes every leaf. Each worker owns a contiguous
// leaf range: it reads that range sequentially in blocks and appends
// hash batches to the memo at its own disjoint offsets, so concurrent
// writes never overlap.
func (ix *Index) warmLeaves() error {
	n := ix.levels[0].n
	leafOff := ix.levels[0].off
	chunk := ix.chunkSize()
	return parallelRanges(n, func(lo, hi int) error {
		span := min(int64(warmReadBlock), int64(hi-lo)*chunk)
		span = span / chunk * chunk // whole chunks, so blocks stay chunk-aligned
		block := make([]byte, span)
		batch := make([]byte, 0, 32*warmBatch)
		first := lo // leaf index of batch[0]
		off, _ := ix.rangeOf(0, lo)
		endOff, endSz := ix.rangeOf(0, hi-1)
		end := endOff + endSz
		flush := func(next int) error {
			if len(batch) == 0 {
				return nil
			}
			if _, err := ix.memo.WriteAt(batch, leafOff+int64(first)*32); err != nil {
				return err
			}
			batch = batch[:0]
			first = next
			return nil
		}
		for off < end {
			sz := min(int64(len(block)), end-off)
			got, err := ix.r.ReadAt(block[:sz], off)
			if err != nil && err != io.EOF {
				return err
			}
			for p := 0; p < got; p += int(chunk) {
				li := int(off/chunk) + p/int(chunk)
				if li >= hi {
					break
				}
				h := hash(block[p:min(p+int(chunk), got)])
				batch = append(batch, h[:]...)
				if len(batch) == cap(batch) {
					if err := flush(li + 1); err != nil {
						return err
					}
				}
			}
			off += int64(got)
		}
		return flush(hi)
	})
}

// warmInternal computes every level above the leaves bottom-up. Each
// level is read whole from the memo (levels shrink by half, so the
// first is at most 32 bytes per chunk), hashed in parallel, and
// written back in one WriteAt.
func (ix *Index) warmInternal() error {
	for lvl := 1; lvl < len(ix.levels); lvl++ {
		c := ix.levels[lvl-1]
		child := make([]byte, 32*c.n)
		if _, err := ix.memo.ReadAt(child, c.off); err != nil {
			return err
		}
		cur := make([]byte, 32*ix.levels[lvl].n)
		if err := parallelRanges(ix.levels[lvl].n, func(lo, hi int) error {
			var in [64]byte
			for i := lo; i < hi; i++ {
				copy(in[:32], child[64*i:64*i+32])
				if 2*i+1 < c.n {
					copy(in[32:], child[64*i+32:64*i+64])
					h := hash(in[:])
					copy(cur[32*i:], h[:])
				} else { // promoted: single child, hash carried verbatim
					copy(cur[32*i:32*i+32], in[:32])
				}
			}
			return nil
		}); err != nil {
			return err
		}
		if _, err := ix.memo.WriteAt(cur, ix.levels[lvl].off); err != nil {
			return err
		}
	}
	return nil
}

// parallelRanges splits [0,n) into one contiguous range per core and
// runs fn on each range concurrently.
func parallelRanges(n int, fn func(lo, hi int) error) error {
	w := runtime.GOMAXPROCS(0)
	if w > n {
		w = n
	}
	if w <= 1 {
		return fn(0, n)
	}
	per := (n + w - 1) / w
	errs := make([]error, w)
	var wg sync.WaitGroup
	for i := range w {
		lo, hi := i*per, min((i+1)*per, n)
		if lo >= hi {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = fn(lo, hi)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
