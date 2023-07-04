package cmd

import (
	"crypto/md5"
	"fmt"
	"io"
)

// md5 encpyt
func md5Sign(str string) string {
	w := md5.New()
	io.WriteString(w, str)
	md5Str := fmt.Sprintf("%x", w.Sum(nil))
	return md5Str
}
