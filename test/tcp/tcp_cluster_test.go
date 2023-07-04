package test

import (
	"fmt"
	"github.com/kerwenwwer/xdp-gossip"
	"testing"
	"time"
)

// 完整测试用例-在本地启动四个节点，构成一个Gossip集群（TCP）
func TestTCPCluster(t *testing.T) {

	fmt.Println("---- Start a gossip cluster (TCP) ----")

	//使用TCP连接集群节点
	protocol = "TCP"

	//先启动节点A（初始节点）
	nodeA()
	//启动节点B
	nodeB()
	//启动节点C
	nodeC()
	//启动节点D
	nodeD()

	//延迟10秒
	time.Sleep(10 * time.Second)

	//结束测试
	fmt.Println("---- End ----")
}

var protocol string

// 运行节点A（初始节点）
func nodeA() {
	//配置节点A的本地节点列表nodeList参数
	nodeList := pekonode.NodeList{
		Protocol:  protocol,   //集群节点连接所使用的网络协议
		SecretKey: "test_key", //密钥，集群中的各个节点的密钥需保持一致，否则无法连接集群
		IsPrint:   true,       //是否在控制台输出日志信息
	}

	//创建节点A及其本地节点列表
	nodeList.New(pekonode.Node{
		Addr:        "0.0.0.0",   //本地节点IP地址，公网环境下请填写公网IP
		Port:        8000,        //本地节点端口号
		Name:        "A-server",  //节点名称，自定义填写
		PrivateData: "test-data", //节点私有数据内容，自定义填写，可以填一些节点基本信息
	})

	//因为是第一个启动的节点，所以不需要用Set函数添加其他节点

	//本地节点加入Gossip集群，本地节点列表与集群中的各个节点所存储的节点列表进行数据同步
	nodeList.Join()

	//延迟3秒
	time.Sleep(3 * time.Second)
}

// 运行节点B
func nodeB() {
	//配置节点B的本地节点列表nodeList参数
	nodeList := pekonode.NodeList{
		Protocol:  protocol, //集群节点连接所使用的网络协议
		SecretKey: "test_key",
		IsPrint:   true,
	}

	//创建节点B及其本地节点列表
	nodeList.New(pekonode.Node{
		Addr:        "0.0.0.0",
		Port:        8001,
		Name:        "B-server",
		PrivateData: "test-data",
	})

	//将初始节点A的信息加入到B节点的本地节点列表当中
	nodeList.Set(pekonode.Node{
		Addr:        "0.0.0.0",
		Port:        8000,
		Name:        "A-server",
		PrivateData: "test-data",
	})

	//调用Join后，节点B会自动与节点A进行数据同步
	nodeList.Join()

	//延迟10秒
	time.Sleep(10 * time.Second)
}

// 运行节点C
func nodeC() {
	nodeList := pekonode.NodeList{
		Protocol:  protocol, //集群节点连接所使用的网络协议
		SecretKey: "test_key",
		IsPrint:   true,
	}

	//创建节点C及其本地节点列表
	nodeList.New(pekonode.Node{
		Addr:        "0.0.0.0",
		Port:        8002,
		Name:        "C-server",
		PrivateData: "test-data",
	})

	//也可以在加入集群之前，在本地节点列表中添加多个节点信息
	nodeList.Set(pekonode.Node{
		Addr:        "0.0.0.0",
		Port:        8000,
		Name:        "A-server",
		PrivateData: "test-data",
	})
	nodeList.Set(pekonode.Node{
		Addr:        "0.0.0.0",
		Port:        8001,
		Name:        "B-server",
		PrivateData: "test-data",
	})

	//在加入集群后，节点C将会与上面的节点A及节点B进行数据同步
	nodeList.Join()

	//延迟10秒
	time.Sleep(10 * time.Second)

	//获取本地节点列表
	list := nodeList.Get()
	fmt.Println("Node list::", list) //打印节点列表

	//在集群中发布新的元数据信息
	nodeList.Publish([]byte("test metadata"))

	//读取本地元数据信息
	metadata := nodeList.Read()
	fmt.Println("Metadata:", string(metadata)) //打印元数据信息

	//停止节点C的心跳广播服务（节点C暂时下线）
	nodeList.Stop()

	//延迟30秒
	time.Sleep(30 * time.Second)

	//因为之前节点C下线，C的本地节点列表无法接收到各节点的心跳数据包，列表被清空
	//所以要先往C的本地节点列表中添加一些集群节点，再调用Start()重启节点D的同步工作
	nodeList.Set(pekonode.Node{
		Addr:        "0.0.0.0",
		Port:        8001,
		Name:        "B-server",
		PrivateData: "test-data",
	})

	//重启节点C的心跳广播服务（节点C重新上线）
	nodeList.Start()
}

// 运行节点D
func nodeD() {
	//配置节点D的本地节点列表nodeList参数
	nodeList := pekonode.NodeList{
		Protocol:  protocol, //集群节点连接所使用的网络协议
		SecretKey: "test_key",
		IsPrint:   true,
	}

	//创建节点D及其本地节点列表
	nodeList.New(pekonode.Node{
		Addr:        "0.0.0.0",
		Port:        8003,
		Name:        "D-server",
		PrivateData: "test-data",
	})

	//将初始节点A的信息加入到D节点的本地节点列表当中
	nodeList.Set(pekonode.Node{
		Addr:        "0.0.0.0",
		Port:        8000,
		Name:        "A-server",
		PrivateData: "test-data",
	})

	//调用Join后，节点D会自动与节点A进行数据同步
	nodeList.Join()

	//延迟5秒
	time.Sleep(5 * time.Second)

	//读取本地元数据信息
	metadata := nodeList.Read()
	fmt.Println("Metadata:", string(metadata)) //打印元数据信息
}
