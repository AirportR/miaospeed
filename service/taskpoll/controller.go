package taskpoll

import (
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/airportr/miaospeed/utils"
	"github.com/airportr/miaospeed/utils/structs"
)

type TPExitCode uint

const (
	TPExitSuccess TPExitCode = iota
	TPExitError
	TPExitInterrupt
)

type taskPollItemWrapper struct {
	TaskPollItem
	counter  atomic.Int64
	exitOnce sync.Once
}

func (tpw *taskPollItemWrapper) OnExit(exitCode TPExitCode) {
	tpw.exitOnce.Do(func() {
		tpw.TaskPollItem.OnExit(exitCode)
	})
}

type TPController struct {
	name        string
	concurrency uint
	interval    time.Duration
	emptyWait   time.Duration

	taskPoll    []*taskPollItemWrapper
	runningTask map[string]int

	current  atomic.Uint32
	pollLock sync.Mutex
}

func (tpc *TPController) Name() string {
	return tpc.name
}

// single thread
func (tpc *TPController) populate() (int, *taskPollItemWrapper) {
	tpc.LockWithTimeit("populate")
	defer tpc.pollLock.Unlock()

	if tpc.current.Load() >= uint32(tpc.concurrency) {
		return 0, nil
	}

	totalWeight := uint(0)
	totalCount := 0
	for _, tp := range tpc.taskPoll {
		totalWeight += tp.Weight()
		totalCount += tp.Count()
	}

	factor := 0
	if totalWeight > 0 {
		factor = rand.Intn(int(totalWeight))
	}

	for _, tp := range tpc.taskPoll {
		factor -= int(tp.Weight())
		if factor < 0 {
			counter := tp.counter.Load()

			tp.counter.Add(1)
			if tp.counter.Load() >= int64(tp.Count()) {
				tpc.removeUnsafe(tp.ID(), TPExitSuccess)
			}

			tpc.current.Add(1)
			tpc.runningTask[tp.ID()] += 1
			return int(counter), tp
		}
	}

	// no task left
	time.Sleep(tpc.emptyWait)

	return 0, nil
}

func (tpc *TPController) release(tpw *taskPollItemWrapper) {
	tpc.LockWithTimeit("release")
	defer tpc.pollLock.Unlock()
	tpc.runningTask[tpw.ID()] -= 1
	inWaitList := structs.MapContains(tpc.taskPoll, func(w *taskPollItemWrapper) string {
		return w.ID()
	}, tpw.ID())

	if !inWaitList && tpc.runningTask[tpw.ID()] == 0 {
		delete(tpc.runningTask, tpw.ID())
		tpw.OnExit(TPExitSuccess)
	}

	if tpc.current.Load() > 0 {
		// atomic
		tpc.current.Add(^uint32(0))
	}
}

func (tpc *TPController) AwaitingCount() int {
	tpc.LockWithTimeit("AwaitingCount")
	//tpc.pollLock.Lock()
	defer tpc.pollLock.Unlock()

	totalCount := 0
	for _, tp := range tpc.taskPoll {
		totalCount += tp.Count() - int(tp.counter.Load())
	}
	return totalCount
}

func (tpc *TPController) UnsafeAwaitingCount() int {
	// This function is not concurrency safe and is only used to get a vague estimate of the number of waits
	// to get the exact number use AwaitingCount
	totalCount := 0
	for _, tp := range tpc.taskPoll {
		totalCount += tp.Count() - int(tp.counter.Load())
	}
	return totalCount
}

func (tpc *TPController) Start() {
	sigTerm := utils.MakeSysChan()

	for {
		select {
		case <-sigTerm:
			utils.DLog("task server shutted down.")
			return
		default:
			if itemIdx, tpw := tpc.populate(); tpw != nil {
				utils.DLogf("Task Poll | Task Populate, poll=%s type=%s id=%s index=%v", tpc.name, tpw.TaskName(), tpw.ID(), itemIdx)
				go func() {
					defer func() {
						_ = utils.WrapErrorPure("Task population err", recover())
						tpc.release(tpw)
					}()
					tpw.Yield(itemIdx, tpc)
				}()
				if tpc.interval > 0 {
					time.Sleep(tpc.interval)
				}
			} else {
				// extra sleep for over-populated punishment
				time.Sleep(40 * time.Millisecond)
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (tpc *TPController) Push(item TaskPollItem) TaskPollItem {
	//tpc.pollLock.Lock()
	tpc.LockWithTimeit("Push")
	defer tpc.pollLock.Unlock()

	tpc.taskPoll = append(tpc.taskPoll, &taskPollItemWrapper{
		TaskPollItem: item,
	})

	return item
}

func (tpc *TPController) removeUnsafe(id string, exitCode TPExitCode) {
	var tp *taskPollItemWrapper = nil
	tpc.taskPoll = structs.Filter(tpc.taskPoll, func(w *taskPollItemWrapper) bool {
		if w.ID() == id {
			tp = w
			return false
		}
		return true
	})

	if tp != nil && exitCode != TPExitSuccess {
		utils.DWarnf("Task Poll | Task interrupted, id=%v reason=%v", id, exitCode)
		tp.OnExit(exitCode)
	}
}

func (tpc *TPController) Remove(id string, exitCode TPExitCode) {
	//tpc.pollLock.Lock()
	tpc.LockWithTimeit("Remove")
	defer tpc.pollLock.Unlock()

	tpc.removeUnsafe(id, exitCode)
}

func (tpc *TPController) LockWithTimeit(funcname string) {
	//t1 := time.Now()
	tpc.pollLock.Lock()
	//t2 := time.Since(t1)
	//if t2 > 1*time.Millisecond {
	//	utils.DBlackholef("Task Poll | LockWithTimeit, timeused=%v, funcname=%s", t2, funcname)
	//}
}

func NewTaskPollController(name string, concurrency uint, interval time.Duration, emptyWait time.Duration) *TPController {
	return &TPController{
		name:        name,
		concurrency: structs.WithInDefault(concurrency, 1, 64, 16),
		interval:    interval,
		emptyWait:   emptyWait,

		runningTask: make(map[string]int),
	}
}
