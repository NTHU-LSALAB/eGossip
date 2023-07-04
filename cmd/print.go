package cmd

import (
	"log"
)

// print message
func (nodeList *NodeList) println(a ...interface{}) {

	if a[0] == "[Error]:" && !nodeList.IsPrint {
		log.Println(a)
	}
	if nodeList.IsPrint {
		log.Println(a)
	}
}
