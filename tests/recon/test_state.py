# -*- coding: utf-8 -*-
"""断点续跑：进度持久化 / 阶段状态 / 目标隔离。"""
import json

from modules.recon.state import RunState


def test_processed_persists_across_reload(tmp_path):
    p = tmp_path / "state.json"
    st = RunState(p, "t1", "standard")
    st.start_stage("probe")
    st.mark_processed("probe", ["a.com|80", "b.com|443"])
    st.finish_stage("probe", "done")

    st2 = RunState(p, "t1", "standard")
    assert st2.is_processed("probe", "a.com|80")
    assert not st2.is_processed("probe", "c.com|80")
    assert st2.stage_status("probe") == "done"
    assert st2.processed_count("probe") == 2


def test_counter_and_reset(tmp_path):
    st = RunState(tmp_path / "s.json", "t1")
    st.set_counter("collect", "count:seed", 10)
    assert st.counter("collect", "count:seed") == 10
    st.start_stage("collect")
    st.reset()
    assert st.counter("collect", "count:seed") is None
    assert st.stage_status("collect") == "pending"


def test_fail_stage_records_reason(tmp_path):
    st = RunState(tmp_path / "s.json", "t1")
    st.start_stage("probe")
    st.fail_stage("probe", "熔断")
    snap = st.snapshot()
    assert snap["stages"]["probe"]["status"] == "failed"
    assert "熔断" in json.dumps(st.data, ensure_ascii=False)


def test_target_mismatch_resets(tmp_path):
    p = tmp_path / "s.json"
    RunState(p, "t1").mark_processed("probe", ["a|80"])
    st = RunState(p, "t2")
    assert st.processed_count("probe") == 0
    assert st.target == "t2"
