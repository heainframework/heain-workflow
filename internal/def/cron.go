package def

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Cron is a 5-field schedule: minute hour day-of-month month day-of-week
// (numbers, *, ranges a-b, lists a,b, steps */n or a-b/n; Sunday = 0 or 7).
type Cron struct {
	min, hour, dom, mon, dow [64]bool
	domAny, dowAny           bool
}

// ParseCron parses a schedule.
func ParseCron(s string) (Cron, error) {
	var c Cron
	f := strings.Fields(s)
	if len(f) != 5 {
		return c, fmt.Errorf("a schedule has 5 fields (minute hour day month weekday)")
	}
	type spec struct {
		set     *[64]bool
		lo, hi  int
		anyFlag *bool
	}
	specs := []spec{{&c.min, 0, 59, nil}, {&c.hour, 0, 23, nil}, {&c.dom, 1, 31, &c.domAny}, {&c.mon, 1, 12, nil}, {&c.dow, 0, 7, &c.dowAny}}
	for i, sp := range specs {
		if f[i] == "*" && sp.anyFlag != nil {
			*sp.anyFlag = true
		}
		for _, part := range strings.Split(f[i], ",") {
			rng, stepS, hasStep := strings.Cut(part, "/")
			step := 1
			if hasStep {
				n, err := strconv.Atoi(stepS)
				if err != nil || n <= 0 {
					return c, fmt.Errorf("field %d: bad step %q", i+1, stepS)
				}
				step = n
			}
			lo, hi := sp.lo, sp.hi
			if rng != "*" {
				a, b, isRange := strings.Cut(rng, "-")
				x, err := strconv.Atoi(a)
				if err != nil {
					return c, fmt.Errorf("field %d: bad value %q", i+1, rng)
				}
				lo, hi = x, x
				if isRange {
					if hi, err = strconv.Atoi(b); err != nil {
						return c, fmt.Errorf("field %d: bad range %q", i+1, rng)
					}
				} else if hasStep {
					hi = sp.hi
				}
			}
			if lo < sp.lo || hi > sp.hi || lo > hi {
				return c, fmt.Errorf("field %d: %q out of %d-%d", i+1, part, sp.lo, sp.hi)
			}
			for v := lo; v <= hi; v += step {
				sp.set[v] = true
			}
		}
	}
	if c.dow[7] {
		c.dow[0] = true
	}
	return c, nil
}

// Matches reports whether t (to the minute) is on the schedule.
func (c Cron) Matches(t time.Time) bool {
	if !c.min[t.Minute()] || !c.hour[t.Hour()] || !c.mon[int(t.Month())] {
		return false
	}
	dom, dow := c.dom[t.Day()], c.dow[int(t.Weekday())]
	switch {
	case c.domAny && c.dowAny:
		return true
	case c.domAny:
		return dow
	case c.dowAny:
		return dom
	}
	return dom || dow // both restricted: either (classic cron)
}

// Next is the first minute after t on the schedule (within ~5 years).
func (c Cron) Next(t time.Time) time.Time {
	t = t.Truncate(time.Minute).Add(time.Minute)
	for i := 0; i < 5*366*24*60; i++ {
		if c.Matches(t) {
			return t
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}
}
