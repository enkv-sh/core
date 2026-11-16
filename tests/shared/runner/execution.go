package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"strconv"
	"strings"
)

const (
	maximumExecutionParallel  = 4
	normalExecutionMemoryMiB  = 8192
	maximumExecutionMemoryMiB = 24576
)

// Requested fields retain only the winning explicit inputs. Execution policy
// is invocation evidence and must not become scenario or continuation authority.
type executionRequest struct {
	Parallel       *int `json:"parallel,omitempty"`
	MemoryLimitMiB *int `json:"memory_limit_mib,omitempty"`
}

type executionCapacity struct {
	Parallel       int `json:"parallel"`
	MemoryLimitMiB int `json:"memory_limit_mib"`
}

type executionPolicy struct {
	Requested executionRequest  `json:"requested"`
	Resolved  executionCapacity `json:"resolved"`
}

func defaultExecutionPolicy() executionPolicy {
	return executionPolicy{Resolved: executionCapacity{Parallel: 4, MemoryLimitMiB: normalExecutionMemoryMiB}}
}

func validateExecutionCapacity(capacity executionCapacity) error {
	return validateExecutionRequest(executionRequest{Parallel: &capacity.Parallel, MemoryLimitMiB: &capacity.MemoryLimitMiB})
}

func validateExecutionRequest(request executionRequest) error {
	if request.Parallel != nil && (*request.Parallel < 1 || *request.Parallel > maximumExecutionParallel) {
		return errors.New("execution parallel must be between 1 and 4")
	}
	if request.MemoryLimitMiB != nil && (*request.MemoryLimitMiB < 1 || *request.MemoryLimitMiB > maximumExecutionMemoryMiB) {
		return errors.New("execution memory limit must be between 1 and 24576 MiB")
	}
	return nil
}

func (request executionRequest) clone() executionRequest {
	if request.Parallel != nil {
		value := *request.Parallel
		request.Parallel = &value
	}
	if request.MemoryLimitMiB != nil {
		value := *request.MemoryLimitMiB
		request.MemoryLimitMiB = &value
	}
	return request
}

func resolveExecution(configured, override executionRequest) (executionPolicy, error) {
	// An override cannot conceal invalid configured input.
	if err := validateExecutionRequest(configured); err != nil {
		return executionPolicy{}, err
	}
	if err := validateExecutionRequest(override); err != nil {
		return executionPolicy{}, err
	}
	requested := configured
	if override.Parallel != nil {
		requested.Parallel = override.Parallel
	}
	if override.MemoryLimitMiB != nil {
		requested.MemoryLimitMiB = override.MemoryLimitMiB
	}
	policy := defaultExecutionPolicy()
	policy.Requested = requested.clone()
	if requested.Parallel != nil {
		policy.Resolved.Parallel = *requested.Parallel
	}
	if requested.MemoryLimitMiB != nil {
		policy.Resolved.MemoryLimitMiB = min(*requested.MemoryLimitMiB, normalExecutionMemoryMiB)
	}
	return policy, nil
}

func (policy executionPolicy) clone() executionPolicy {
	policy.Requested = policy.Requested.clone()
	return policy
}

// Register on the command's actual FlagSet so other options own their values.
// Both command parsers and the installed supervisor use these flag semantics.
func registerExecutionFlags(flags *flag.FlagSet, request *executionRequest) {
	register := func(name string, field **int) {
		flags.Func(name, "", func(value string) error {
			if *field != nil {
				return errors.New("duplicate execution override")
			}
			parsed, err := strconv.Atoi(value)
			if err != nil {
				return errors.New("execution override requires an integer")
			}
			*field = &parsed
			return validateExecutionRequest(*request)
		})
	}
	register("parallel", &request.Parallel)
	register("memory-limit-mib", &request.MemoryLimitMiB)
}

// Bare commands retain their positional arguments. Capacity flags precede
// those arguments, using the standard FlagSet end-of-flags rules.
func parseExecutionPositionals(args []string) ([]string, executionRequest, error) {
	args, _, err := parseRaceArguments(args)
	if err != nil {
		return nil, executionRequest{}, err
	}
	request := executionRequest{}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	registerExecutionFlags(flags, &request)
	if err := flags.Parse(args[1:]); err != nil {
		return nil, executionRequest{}, err
	}
	return append([]string{args[0]}, flags.Args()...), request, nil
}

type executionContextKey struct{}

func withExecutionCapacity(ctx context.Context, policy executionPolicy) context.Context {
	return context.WithValue(ctx, executionContextKey{}, policy.Resolved)
}

// A dispatched independent job receives one slot from its parent's allowance.
// The shared memory ceiling continues to cover the complete invocation.
func withExecutionParallel(ctx context.Context, parallel int) context.Context {
	capacity := executionCapacityFromContext(ctx)
	capacity.Parallel = parallel
	return context.WithValue(ctx, executionContextKey{}, capacity)
}

func executionCapacityFromContext(ctx context.Context) executionCapacity {
	if capacity, present := ctx.Value(executionContextKey{}).(executionCapacity); present {
		return capacity
	}
	// Only a root composition can assign the configured root allowance.
	return executionCapacity{Parallel: 1, MemoryLimitMiB: normalExecutionMemoryMiB}
}

func executionForClass(policy executionPolicy, big bool) executionPolicy {
	policy = policy.clone()
	limit := normalExecutionMemoryMiB
	if big {
		limit = maximumExecutionMemoryMiB
	}
	if policy.Requested.MemoryLimitMiB != nil {
		limit = min(limit, *policy.Requested.MemoryLimitMiB)
	}
	policy.Resolved.MemoryLimitMiB = limit
	return policy
}

func executionWithinContext(ctx context.Context, supplied executionPolicy) (executionPolicy, error) {
	policy, err := resolveExecution(executionRequest{}, supplied.Requested)
	if err != nil {
		return executionPolicy{}, err
	}
	maximum := executionForClass(policy, true).Resolved
	if supplied.Resolved != (executionCapacity{}) {
		if err := validateExecutionCapacity(supplied.Resolved); err != nil {
			return executionPolicy{}, err
		}
		if supplied.Resolved.Parallel > maximum.Parallel || supplied.Resolved.MemoryLimitMiB > maximum.MemoryLimitMiB {
			return executionPolicy{}, errors.New("execution capacity exceeds requested allowance")
		}
		policy.Resolved = supplied.Resolved
	}
	if capacity, present := ctx.Value(executionContextKey{}).(executionCapacity); present {
		if err := validateExecutionCapacity(capacity); err != nil {
			return executionPolicy{}, err
		}
		policy.Resolved.Parallel = min(policy.Resolved.Parallel, capacity.Parallel)
		// The admitted context owns the aggregate ceiling; preparation used
		// the normal ceiling before the complete selection was classified.
		policy.Resolved.MemoryLimitMiB = min(maximum.MemoryLimitMiB, capacity.MemoryLimitMiB)
	} else {
		policy.Resolved.Parallel = 1
	}
	return policy, nil
}

func sameExecutionPolicy(left, right executionPolicy) bool {
	same := func(a, b *int) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
	return left.Resolved == right.Resolved && same(left.Requested.Parallel, right.Requested.Parallel) && same(left.Requested.MemoryLimitMiB, right.Requested.MemoryLimitMiB)
}

// Package and test concurrency share one allowance. Scheduling flags do not
// change the compiler inputs bound by prepared artifacts.
func executionGoArguments(ctx context.Context, args []string) ([]string, error) {
	if len(args) == 0 {
		return args, nil
	}
	switch args[0] {
	case "build", "test", "list", "vet", "run":
	default:
		return args, nil
	}
	capacity := executionCapacityFromContext(ctx)
	if err := validateExecutionCapacity(capacity); err != nil {
		return nil, err
	}
	packages, parallel := capacity.Parallel, capacity.Parallel
	compileOnly := false
	actual := []string{args[0]}
	for i := 1; i < len(args); i++ {
		value := args[i]
		if value == "-args" || value == "--" || args[0] != "test" && !strings.HasPrefix(value, "-") {
			if args[0] == "test" {
				for _, opaque := range args[i+1:] {
					name, _, _ := strings.Cut(strings.TrimLeft(opaque, "-"), "=")
					if strings.HasPrefix(opaque, "-") && name == "test.parallel" {
						return nil, errors.New("test parallel must precede passthrough arguments")
					}
				}
			}
			actual = append(actual, args[i:]...)
			break
		}
		name, number, assigned := strings.Cut(strings.TrimLeft(value, "-"), "=")
		if name == "p" || args[0] == "test" && (name == "parallel" || name == "test.parallel") {
			if !assigned {
				if i+1 == len(args) {
					return nil, errors.New("Go concurrency value unavailable")
				}
				i++
				number = args[i]
			}
			count, err := strconv.Atoi(number)
			if err != nil || count < 1 {
				return nil, errors.New("Go concurrency value refused")
			}
			if name == "p" {
				packages = min(packages, count)
			} else {
				parallel = min(capacity.Parallel, count)
			}
			continue
		}
		if args[0] == "test" && name == "c" {
			compileOnly = true
			if assigned {
				var err error
				compileOnly, err = strconv.ParseBool(number)
				if err != nil {
					return nil, err
				}
			}
		}
		actual = append(actual, value)
		if strings.HasPrefix(value, "-") && !assigned && goFlagTakesValue(name) {
			if i+1 == len(args) {
				return nil, errors.New("Go flag value unavailable")
			}
			i++
			actual = append(actual, args[i])
		}
	}
	prefix := []string{actual[0]}
	if args[0] == "test" && !compileOnly {
		packages = min(packages, capacity.Parallel/parallel)
		prefix = append(prefix, "-parallel="+strconv.Itoa(parallel))
	}
	prefix = append(prefix, "-p="+strconv.Itoa(packages))
	return append(prefix, actual[1:]...), nil
}

// These value flags are defined by the pinned Go toolchain's build/test
// commands. Consume their values before interpreting scheduling flags.
func goFlagTakesValue(name string) bool {
	name = strings.TrimPrefix(name, "test.")
	switch name {
	case "C", "o", "asmflags", "compiler", "buildmode", "gcflags", "gccgoflags",
		"overlay", "installsuffix", "ldflags", "pgo", "pkgdir", "tags", "toolexec",
		"mod", "modfile", "covermode", "coverpkg", "coverprofile", "exec", "f", "reuse",
		"debug-actiongraph", "debug-runtime-trace", "debug-trace",
		"bench", "benchtime", "blockprofile", "blockprofilerate", "count", "cpu",
		"cpuprofile", "fuzz", "fuzztime", "fuzzminimizetime", "list", "memprofile",
		"memprofilerate", "mutexprofile", "mutexprofilefraction", "outputdir", "run",
		"skip", "timeout", "trace", "shuffle", "vet":
		return true
	}
	return false
}
