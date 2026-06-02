export default function Debug() {
  const handleSeed = async () => {
    await fetch("/api/seed", { body: JSON.stringify({ reset: true }) });
  };
  const handleWipe = () => fetch("/api/debug/reset");
  return <button onClick={handleSeed}>Seed Database</button>;
}
