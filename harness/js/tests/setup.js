// Frozen verification context.
// vitest の setupFiles は pytest の conftest.py に相当する「グローバル注入点」。
// ここと vitest.config.js が凍結マニフェストに入っていないと攻撃A2が通る。
