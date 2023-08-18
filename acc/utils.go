package main

import (
	"math/rand"
)

func Pad127(in []byte, res []Fr) {
	if len(in) != 127 {
		if len(in) > 127 {
			in = in[:127]
		} else {
			padding := make([]byte, 127-len(in))
			in = append(in, padding...)
		}
	}

	tmp := make([]byte, 32)
	copy(tmp[:31], in[:31])

	t := in[31] >> 6
	tmp[31] = in[31] & 0x3f
	res[0].SetBytes(tmp)

	var v byte
	for i := 32; i < 64; i++ {
		v = in[i]
		tmp[i-32] = (v << 2) | t
		t = v >> 6
	}
	t = v >> 4
	tmp[31] &= 0x3f
	res[1].SetBytes(tmp)

	for i := 64; i < 96; i++ {
		v = in[i]
		tmp[i-64] = (v << 4) | t
		t = v >> 4
	}
	t = v >> 2
	tmp[31] &= 0x3f
	res[2].SetBytes(tmp)

	for i := 96; i < 127; i++ {
		v = in[i]
		tmp[i-96] = (v << 6) | t
		t = v >> 2
	}
	tmp[31] = t & 0x3f
	res[3].SetBytes(tmp)
}

func Unpad127(in []Fr, out []byte) {
	if len(in) != 4 {
		panic("invalid in length")
	}

	if len(out) < 127 {
		panic("invalid out length")
	}

	tmp := in[0].Bytes()
	for i := 0; i < 32; i++ {
		out[i] = tmp[i]
	}

	tmp = in[1].Bytes()
	v := tmp[0]
	out[31] |= v << 6

	for i := 32; i < 63; i++ {
		next := tmp[i-32+1]

		out[i] = v >> 2
		out[i] |= next << 6

		v = next
	}

	out[63] = (v << 2) >> 4
	tmp = in[2].Bytes()
	v = tmp[0]
	out[63] |= v << 4

	for i := 64; i < 95; i++ {
		next := tmp[i-64+1]

		out[i] = v >> 4
		out[i] |= next << 4

		v = next
	}
	out[95] = (v << 2) >> 6
	tmp = in[3].Bytes()
	v = tmp[0]
	out[95] |= v << 2

	for i := 96; i < 127; i++ {
		next := tmp[i-96+1]

		out[i] = v >> 6
		out[i] |= next << 2

		v = next
	}
}

func split(data []byte) []Fr {
	num := (len(data)-1)/ShardingLen + 1

	atom := make([]Fr, num*4)

	padding := make([]byte, ShardingLen*num-len(data))
	data = append(data, padding...)

	for i := 0; i < num; i++ {
		Pad127(data[ShardingLen*i:ShardingLen*(i+1)], atom[4*i:4*i+4])
	}

	return atom
}

func genRandom(len int) []byte {
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
