package kzg

import (
	"math/rand"
)

func Split(data []byte) []Fr {
	num := (len(data)-1)/ShardingLen + 1

	atom := make([]Fr, num)

	for i := 0; i < num-1; i++ {
		atom[i].SetBytes(data[ShardingLen*i : ShardingLen*(i+1)])
	}

	atom[num-1].SetBytes(data[ShardingLen*(num-1):])

	return atom
}

func GenRandom(len int) []byte {
	res := make([]byte, len)
	for i := 0; i < len; i += 7 {
		val := rand.Int63()
		for j := 0; i+j < len && j < 7; j++ {
			res[i+j] = byte(val)
			val >>= 8
		}
	}
	return res
}
