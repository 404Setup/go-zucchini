package main

import (
	"fmt"
	"io"
	"strings"
)

type optionSpec struct {
	requiresValue bool
}

type commandSpec struct {
	name        string
	usage       string
	argCount    int
	options     map[string]optionSpec
	description string
}

var commandList = []commandSpec{
	{name: "gen", usage: "gen <old_file> <new_file> <patch_file> [--raw | --impose <matches>] [--keep]", argCount: 3, description: "Generate a patch", options: map[string]optionSpec{"raw": {}, "impose": {requiresValue: true}, "keep": {}}},
	{name: "apply", usage: "apply <old_file> <patch_file> <new_file> [--sha256 <digest>] [--keep]", argCount: 3, description: "Apply a patch", options: map[string]optionSpec{"sha256": {requiresValue: true}, "keep": {}}},
	{name: "verify", usage: "verify <patch_file>", argCount: 1, description: "Validate a patch"},
	{name: "read", usage: "read <executable> [--dump]", argCount: 1, description: "Inspect executable references", options: map[string]optionSpec{"dump": {}}},
	{name: "detect", usage: "detect <archive_file>", argCount: 1, description: "Detect embedded executables"},
	{name: "match", usage: "match <old_file> <new_file> [--impose <matches>]", argCount: 2, description: "Match executable elements", options: map[string]optionSpec{"impose": {requiresValue: true}}},
	{name: "crc32", usage: "crc32 <file>", argCount: 1, description: "Calculate CRC32"},
	{name: "suffix-array", usage: "suffix-array <file>", argCount: 1, description: "Build a suffix array"},
}

type parsedCommand struct {
	spec       *commandSpec
	positional []string
	flags      map[string]bool
	values     map[string]string
	help       bool
	version    bool
}

func (p *parsedCommand) has(name string) bool     { return p.flags[name] }
func (p *parsedCommand) value(name string) string { return p.values[name] }

func commandByName(name string) *commandSpec {
	name = strings.ReplaceAll(name, "_", "-")
	for i := range commandList {
		if commandList[i].name == name {
			return &commandList[i]
		}
	}
	return nil
}

func parseCommandLine(args []string) (*parsedCommand, error) {
	parsed := &parsedCommand{flags: make(map[string]bool), values: make(map[string]string)}
	if len(args) == 0 {
		return nil, fmt.Errorf("missing command")
	}

	first := args[0]
	if first == "help" || first == "-h" || first == "--help" {
		parsed.help = true
		return parsed, nil
	}
	if first == "version" || first == "-version" || first == "--version" {
		parsed.version = true
		return parsed, nil
	}

	commandIndex := -1
	if spec := commandByName(first); spec != nil && !strings.HasPrefix(first, "-") {
		parsed.spec = spec
		commandIndex = 0
	} else {
		for i, arg := range args {
			if arg == "--" {
				break
			}
			name, isSwitch, err := parseSwitchName(arg)
			if err != nil {
				return nil, err
			}
			if !isSwitch {
				continue
			}
			if spec := commandByName(name); spec != nil {
				if parsed.spec != nil {
					return nil, fmt.Errorf("commands --%s and --%s cannot be combined", parsed.spec.name, spec.name)
				}
				parsed.spec, commandIndex = spec, i
			}
		}
	}
	if parsed.spec == nil {
		return nil, fmt.Errorf("unknown or missing command %q", first)
	}

	optionsDone := false
	for i := 0; i < len(args); i++ {
		if i == commandIndex {
			continue
		}
		arg := args[i]
		if !optionsDone && arg == "--" {
			optionsDone = true
			continue
		}
		if optionsDone || !strings.HasPrefix(arg, "-") || arg == "-" {
			parsed.positional = append(parsed.positional, arg)
			continue
		}

		name, inlineValue, hasInlineValue, err := parseOption(arg)
		if err != nil {
			return nil, err
		}
		if commandByName(name) != nil {
			return nil, fmt.Errorf("more than one command was specified")
		}
		if name == "help" || name == "h" {
			if hasInlineValue {
				return nil, fmt.Errorf("option --help does not accept a value")
			}
			parsed.help = true
			continue
		}
		option, ok := parsed.spec.options[name]
		if !ok {
			return nil, fmt.Errorf("option --%s is not valid for %s", name, parsed.spec.name)
		}
		if parsed.flags[name] {
			return nil, fmt.Errorf("option --%s was specified more than once", name)
		}
		parsed.flags[name] = true
		if option.requiresValue {
			value := inlineValue
			if !hasInlineValue {
				if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
					return nil, fmt.Errorf("option --%s requires a value", name)
				}
				i++
				value = args[i]
			}
			if value == "" {
				return nil, fmt.Errorf("option --%s requires a non-empty value", name)
			}
			parsed.values[name] = value
		} else if hasInlineValue {
			return nil, fmt.Errorf("option --%s does not accept a value", name)
		}
	}

	if parsed.help {
		return parsed, nil
	}
	if len(parsed.positional) != parsed.spec.argCount {
		return nil, fmt.Errorf("%s expects %d file argument(s), got %d", parsed.spec.name, parsed.spec.argCount, len(parsed.positional))
	}
	if parsed.spec.name == "gen" && parsed.has("raw") && parsed.has("impose") {
		return nil, fmt.Errorf("options --raw and --impose are mutually exclusive")
	}
	return parsed, nil
}

func parseSwitchName(arg string) (string, bool, error) {
	if !strings.HasPrefix(arg, "-") || arg == "-" {
		return "", false, nil
	}
	name, _, hasValue, err := parseOption(arg)
	if err != nil {
		return "", true, err
	}
	if hasValue {
		return "", true, fmt.Errorf("command %q cannot have a value", arg)
	}
	return name, true, nil
}

func parseOption(arg string) (name, value string, hasValue bool, err error) {
	trimmed := ""
	if strings.HasPrefix(arg, "--") {
		trimmed = arg[2:]
	} else if strings.HasPrefix(arg, "-") {
		trimmed = arg[1:]
	}
	if trimmed == "" || strings.HasPrefix(trimmed, "-") {
		return "", "", false, fmt.Errorf("invalid option %q", arg)
	}
	if before, after, found := strings.Cut(trimmed, "="); found {
		trimmed, value, hasValue = before, after, true
	}
	name = strings.ReplaceAll(trimmed, "_", "-")
	if name == "" {
		return "", "", false, fmt.Errorf("invalid option %q", arg)
	}
	return name, value, hasValue, nil
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Zucchini 2.0")
	fmt.Fprintln(w, "Usage: zucchini <command> [options]")
	fmt.Fprintln(w, "       zucchini -<command> [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	for _, command := range commandList {
		fmt.Fprintf(w, "  %-14s %s\n", command.name, command.description)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Use 'zucchini <command> --help' for command syntax.")
}

func printCommandUsage(w io.Writer, command *commandSpec) {
	fmt.Fprintf(w, "Usage: zucchini %s\n", command.usage)
	fmt.Fprintf(w, "       zucchini -%s\n", command.usage)
	if command.name == "gen" || command.name == "apply" {
		fmt.Fprintln(w, "\n--keep retains a partial output file when the operation fails.")
	}
	if command.name == "apply" {
		fmt.Fprintln(w, "--sha256 requires the reconstructed file to match a trusted SHA-256 digest.")
	}
	if command.name == "gen" || command.name == "match" {
		fmt.Fprintln(w, "Imposed matches use old_offset+old_size=new_offset+new_size.")
	}
}
