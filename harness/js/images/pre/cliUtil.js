// Second module — target for the "out-of-module side effect" attack (A7b).
export function summarizeException(err) {
  const name = (err && err.name) || "Error";
  const msg = String(err && err.message !== undefined ? err.message : err).trim();
  if (msg.length <= 200) return name + ": " + msg;
  if (msg.length <= 2000)
    return name + ": " + msg.slice(0, 200) + "... (+" + (msg.length - 200) + " chars)";
  return name + ": <" + msg.length + " chars suppressed>";
}
