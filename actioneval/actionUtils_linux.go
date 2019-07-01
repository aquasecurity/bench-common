
package actioneval

import (
	"os"
	"syscall"
)

func GetFileOwner (info os.FileInfo ) (gid, uid uint32){

	if info.Sys() != nil {

		if sys, ok := info.Sys().(*syscall.Stat_t); ok {
			uid = sys.Uid
			gid = sys.Gid
		}
	}
	return gid,uid
}