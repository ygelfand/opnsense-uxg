module github.com/ygelfand/opnsense-uxg

go 1.25.0

require (
	github.com/browningluke/opnsense-go v0.25.0
	github.com/golang/snappy v1.0.0
	github.com/jamesbraid/unifi-emu v0.5.5
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.8 // indirect
	golang.org/x/text v0.28.0 // indirect
)

replace github.com/browningluke/opnsense-go => github.com/ygelfand/opnsense-go v0.0.0-20261014121528-b0d55b7f7929
