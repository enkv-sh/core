//go:build darwin || linux

package configuration

import (
	"fmt"
	"os"
	"reflect"
	"syscall"
)

func nativeChange(v os.FileInfo) string {
	s, ok := v.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	value := reflect.ValueOf(s).Elem()
	for _, name := range []string{"Ctim", "Ctimespec"} {
		field := value.FieldByName(name)
		if field.IsValid() {
			return fmt.Sprint(field.Interface())
		}
	}
	return ""
}

func sameNativeOwner(a, b os.FileInfo) bool {
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && x.Uid == y.Uid && x.Gid == y.Gid
}
