module main

go 1.13

require (
	github.com/antonmedv/expr v1.8.2
	github.com/coreos/go-etcd v2.0.0+incompatible // indirect
	github.com/cpuguy83/go-md2man v1.0.10 // indirect
	github.com/crowdsecurity/crowdsec v0.0.1
	github.com/davecgh/go-spew v1.1.1
	github.com/denisbrodbeck/machineid v1.0.1
	github.com/dghubble/sling v1.3.0
	github.com/enescakir/emoji v1.0.0
	github.com/fatih/color v1.9.0 // indirect
	github.com/fogleman/gg v1.3.0 // indirect
	github.com/golang/freetype v0.0.0-20170609003504-e2365dfdc4a0 // indirect
	github.com/hashicorp/go-version v1.2.0
	github.com/jamiealquiza/tachymeter v2.0.0+incompatible
	github.com/jpoles1/gopherbadger v2.2.0+incompatible // indirect
	github.com/olekukonko/tablewriter v0.0.4
	github.com/prometheus/client_golang v1.5.1
	github.com/prometheus/client_model v0.2.0
	github.com/prometheus/prom2json v1.3.0
	github.com/sevlyar/go-daemon v0.1.5
	github.com/sirupsen/logrus v1.5.0
	github.com/spf13/cobra v0.0.7
	github.com/ugorji/go/codec v0.0.0-20181204163529-d75b2dcb6bc8 // indirect
	golang.org/x/image v0.0.0-20200119044424-58c23975cae1 // indirect
	//	time v0.0.0-00010101000000-000000000000 // indirect
	//github.com/sirupsen/logrus v1.4.2
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	gopkg.in/yaml.v2 v2.2.8
)

replace log => github.com/sirupsen/logrus v1.4.2
