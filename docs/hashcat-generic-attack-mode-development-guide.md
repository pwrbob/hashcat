
# Development Guide For Attack-Mode 8: Generic Password Candidate Generator Mode

---

## General

The generic attack mode was created to support advanced password candidate generators. But what is an advanced password generator? 

We define it first by a generator that can do more than the embedded attack-mode in hashcat, which are mostly designed so that they work best on a GPU. In hashcat we have generators which do simply reading a wordlist and applying rules, or generating a virtual wordlist from a mask, and combinations out of this. the reason for the simple generators in hashcat is because they allow for a multiplier logic, so we can gain a maximum performance even for fast hashes. But for fast hashes it might be not so relevant to extreme fast candidate generation, and other features become more relevant. So everything that falls out of the existing candidate generator logic is an advanced generator.

Examples of advanced generators include:

- AI-driven candidate generation
- Reading data from a network stream
- Statistical models that adapt dynamically
- Logic-based systems for contextualized passwords
- Your ideas

Such generators are often implemented as standalone tools and connected to Hashcat through the stdin interface. However, that approach comes with limitations and bottlenecks, which are discussed in the user guide: docs/hashcat-generic-attack-mode.md. If you have not read it yet, start there.

This document explains how to add your own “feed” to be used with attack mode 8.

## What is a Feed?

A feed is a dynamically loaded library (.so, .dll, .dylib) that Hashcat loads at startup. Attack mode 8 itself does not provide generator logic. Instead, the user selects a feed by specifying its filename as the first parameter on the command line.

This open design allows for:

- An unlimited number of plugins that can ship with Hashcat core
- Custom feeds for specialized workflows or client requirements

## Example Feeds

We provide two sample feeds:

1. feed_wordlist

	- A simple wordlist loader, similar to -a 0
	- Does not support loading from folders
	- Much higher performance than classical -a 0 due to improved seeking
	- Uses a seek database instead of the traditional dictstat file, allowing efficient random access without repeatedly calling next()
	- Especially beneficial on multi-GPU systems

2. rust_dummy

	- A skeleton implementation written in Rust
	- Demonstrates two things:
	  a) a feed that does not report a keyspace
	  b) feeds do not need to be written in C to be efficient

## Design Philosophy

The interface was intentionally designed to be as simple and straightforward as possible. This allows you to focus on generating high-quality password candidates without needing deep knowledge of Hashcat internals. The simplicity also makes it easy to integrate with code-generation tools or AI assistants.

Early experiments showed success reimplementing legacy Hashcat attacks such as -a 2 (permutation attack) and -a 5 (table attack).

## Required Functions

There are seven functions you can implement. In theory, only one thread_next() is mandatory, but for a proper implementation you will likely want to define several.

### Main Function

```
int thread_next (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, const u8 **out_buf)
```

This function is called whenever Hashcat needs the next password candidate. You must set the output buffer pointer and return the length of the candidate. The two custom data types are simple structures holding only basic primitives.

### Full Function Set

```
bool global_init     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, hashcat_ctx_t *hashcat_ctx)
void global_term     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, hashcat_ctx_t *hashcat_ctx)
u64  global_keyspace (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, hashcat_ctx_t *hashcat_ctx)
bool thread_init     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx)
void thread_term     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx)
int  thread_next     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, const u8 **out_buf)
bool thread_seek     (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, const u64 offset)
```

## Global vs Thread Context

Hashcat supports compute devices of very different performance levels. For example, a session may include one CPU and five GPUs, each with different speeds. To feed each device efficiently, Hashcat creates a separate thread per device.

This is why there are two context structures:

- global_ctx: shared across all threads
- thread_ctx: unique to each thread

## Global vs Thread Functions

There are two categories of functions:

- Global functions: initialization, termination, and keyspace reporting
- Thread functions: initialization, termination, seeking, and producing the next candidate

Examples:

- Global init: Used for setup work that all threads can share. For example, building a lookup table of byte offsets for each word in a wordlist. Each thread then benefits from this shared data.
- Thread init: Used for thread-specific setup. For example, each thread could open its own file handle instead of sharing one global handle. This avoids synchronization overhead and boosts performance.

This model gives you flexibility. You can centralize some work in the global functions or let each thread manage its own resources. Both approaches are valid depending on your use case.

## Advantages Over stdin

Unlike feeding candidates over stdin, attack mode 8 allows:

- Independent threads per compute device
- No mutex bottlenecks on shared pipes
- The option for each thread to open its own resources (files, sockets, databases)
- Higher performance and scalability

