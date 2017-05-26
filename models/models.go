package models

import (
	"fmt"
	"time"
)

func Dig(d string, ns []string) int {

	for _, v := range ns {

		remsg, err := send(v, d, 1, 500*time.Millisecond)
		fmt.Println(remsg)
		if err != nil {
			continue
		}

		if remsg.MsgHdr.Authoritative {
			return 5
		}

		length := len(remsg.Ns)
		k := 0

		for _, v := range remsg.Ns {
			if ns, ok := v.(*NS); ok {
				fmt.Println(ns.Ns)
			}
		}
		for _, v := range remsg.Answer {
			if a, ok := v.(*A); ok {
				fmt.Println(a.A.String())
			}
		}
		if k == 0 {
			return 2
		}
		if k > 0 && k < length {
			return 3
		}
		if k == length {
			return 4
		}

	}
	return 6

}
