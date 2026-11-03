// SPDX-License-Identifier: GPL-3.0-only
package cmd

type nodeSignals struct{ reload, status <-chan struct{} }
