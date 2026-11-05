package statistic

type RequestNotify func(c Tracker)

var DefaultRequestNotify RequestNotify
