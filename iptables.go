package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
)

type Table = string

type Chain = string

type Rules = []string

type TableContent struct {
	ChainCounters []string
	ChainRules    map[Chain]Rules
	ChainOrder    []Chain
}

type Iptables map[Table]TableContent

var ruleRegex *regexp.Regexp

func init() {
	ruleRegex = regexp.MustCompile(`[^\s"]+|"[^"]*"`)
}

func iptablesSave() (iptables Iptables, err error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(config.bin + "-save")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("%+v: %s", err, stderr.String())
	}

	return newIptables(stdout.String()), nil
}

func iptablesRestore(iptables Iptables) (err error) {
	cmd := exec.Command(config.bin + "-restore")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return
	}

	io.WriteString(stdin, iptables.Save())
	stdin.Close()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%+v: %s", err, out)
	}
	return
}

func newIptables(iptablesSave string) Iptables {
	iptables := make(Iptables)

	scanner := bufio.NewScanner(strings.NewReader(iptablesSave))
	var table Table
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "*") {
			table = line[1:]
			iptables[table] = TableContent{
				ChainRules: make(map[Chain]Rules),
			}
			continue
		}

		if strings.HasPrefix(line, ":") {
			chain := strings.Split(line, " ")[0][1:]
			if content, ok := iptables[table]; ok {
				content.ChainCounters = append(content.ChainCounters, line)
				content.ChainOrder = append(content.ChainOrder, chain)
				iptables[table] = content
			}
			continue
		}

		if strings.HasPrefix(line, "-A") {
			parts := ruleRegex.FindAllString(line, -1)
			chain, rules := parts[1], parts[2:]
			iptables[table].ChainRules[chain] = append(iptables[table].ChainRules[chain],
				strings.Join(rules, " "))
			continue
		}
	}
	return iptables
}

func (iptables Iptables) Insert(bpfCode string) {
	for table, content := range iptables {
		for chain, rules := range content.ChainRules {
			insertRules := Rules{}
			for i, rule := range rules {
				parts := ruleRegex.FindAllString(rule, -1)
				for j, part := range parts {
					if part == "-j" || part == "-g" {
						parts = parts[:j]
						break
					}
				}
				parts = append(parts,
					"-m", "bpf", "--bytecode", fmt.Sprintf(`"%s"`, bpfCode),
					"-j", "LOG", "--log-prefix", fmt.Sprintf(`"%d/%s/%s"`, i, table, chain))

				insertRules = append(insertRules, strings.Join(parts, " "))
			}

			newRules := Rules{}
			for i := 0; i < len(insertRules); i++ {
				newRules = append(newRules, insertRules[i], rules[i])
			}
			content.ChainRules[chain] = newRules
		}
	}
}

func (iptables Iptables) Copy() Iptables {
	newIptables := Iptables{}
	for table, content := range iptables {
		newIptables[table] = TableContent{
			ChainCounters: make([]string, len(content.ChainCounters)),
			ChainRules:    make(map[Chain]Rules),
			ChainOrder:    make([]Chain, len(content.ChainOrder)),
		}
		copy(newIptables[table].ChainCounters, content.ChainCounters)
		copy(newIptables[table].ChainOrder, content.ChainOrder)
		for chain, rules := range content.ChainRules {
			newIptables[table].ChainRules[chain] = make(Rules, len(rules))
			copy(newIptables[table].ChainRules[chain], rules)
		}
	}
	return newIptables
}

func (iptables Iptables) Save() string {
	lines := []string{}
	for table, content := range iptables {
		lines = append(lines, fmt.Sprintf("*%s", table))
		for _, statement := range content.ChainCounters {
			lines = append(lines, statement)
		}
		for _, chain := range content.ChainOrder {
			if rules, ok := content.ChainRules[chain]; ok {
				for _, rule := range rules {
					lines = append(lines, fmt.Sprintf("-A %s %s", chain, rule))
				}
			}
		}
		lines = append(lines, "COMMIT\n")
	}
	return strings.Join(lines, "\n")
}
