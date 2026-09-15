from censorbot.benchmark import run_benchmark
from censorbot.policy import get_policy


def test_benchmark_no_leaks_on_maximum():
    result = run_benchmark(get_policy("maximum"), use_spacy=False)
    # the whole point: deterministic + resolved entities in the fixtures must not
    # survive into output.
    assert result.leak_rate == 0.0, result.report()
    assert result.recall == 1.0


def test_benchmark_round_trip_perfect():
    result = run_benchmark(get_policy("maximum"), use_spacy=False)
    assert result.round_trip_fidelity == 1.0, result.report()
