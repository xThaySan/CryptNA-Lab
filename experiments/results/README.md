# Official result evidence

This directory receives raw CSV files, benchmark output, environment metadata, and eBPF logs produced by the experiment scripts. Results used in a publication should be committed together with the exact source revision that produced them.

Do not copy old summaries over a new campaign. Start from an empty directory while preserving this file, run `scripts/capture_environment.sh`, execute the documented workflow, and verify that every trial completed without failures before generating the final summary.

The summary script is fail-closed: the official workflow requires ten complete paired dry-run trials, ten complete paired XFRM trials, their status files, observer-cost measurements, multi-PEP benchmark output, and captured environment metadata. It will not generate publication wording from a partial campaign.
