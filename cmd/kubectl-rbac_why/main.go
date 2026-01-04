package main

import (
	"os"

	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/hardik/kubectl-rbac-why/pkg/cmd/cani"
)

func main() {
	flags := pflag.NewFlagSet("kubectl-rbac_why", pflag.ExitOnError)
	pflag.CommandLine = flags

	streams := genericclioptions.IOStreams{
		In:     os.Stdin,
		Out:    os.Stdout,
		ErrOut: os.Stderr,
	}

	cmd := cani.NewCmdRbacWhy(streams)

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
