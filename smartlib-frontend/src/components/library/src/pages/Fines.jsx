import React, { useEffect, useMemo, useState } from "react";

// Fines Dashboard (frontend-only, mock data)
// Expected JSON (as per DB helpers / DB.md):
// - For user fines: array of items with fields:
//   { fine_id, amount, paid_status ('unpaid'|'paid'), payment_date (nullable), title }
// - For admin all fines, items may also include: { user_name, book_title, borrow_id }
// This page uses inline mock data and optimistic UI. Replace the mock load with a real fetch when backend is ready.

const MOCK_USER_FINES = [
  { fine_id: 101, amount: 150.0, paid_status: "unpaid", payment_date: null, title: "Clean Code" },
  { fine_id: 102, amount: 80.5, paid_status: "paid", payment_date: "2025-10-02T10:00:00Z", title: "The Pragmatic Programmer" },
  { fine_id: 103, amount: 45.25, paid_status: "unpaid", payment_date: null, title: "Refactoring" }
];

const Fines = () => {
  const [fines, setFines] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [paying, setPaying] = useState({});
  const [payAllLoading, setPayAllLoading] = useState(false);

  const normalizeFines = (payload) => {
    if (Array.isArray(payload)) return payload;
    if (payload && Array.isArray(payload.fines)) return payload.fines;
    return [];
  };

  const loadFines = async () => {
    setLoading(true);
    setError("");
    try {
      // Simulate network delay using inline mock data to match DB schema
      await new Promise((r) => setTimeout(r, 300));
      const data = normalizeFines(MOCK_USER_FINES);
      setFines(data);
    } catch (e) {
      setError("Failed to load fines.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFines();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const outstandingTotal = useMemo(() => {
    return fines
      .filter((f) => String(f?.paid_status || "").toLowerCase() !== "paid")
      .reduce((sum, f) => sum + Number(f?.amount || 0), 0);
  }, [fines]);

  const unpaidIds = useMemo(() => {
    return fines
      .filter((f) => String(f?.paid_status || "").toLowerCase() !== "paid")
      .map((f) => f.fine_id)
      .filter((id) => id != null);
  }, [fines]);

  const handlePay = async (fineId) => {
    if (fineId == null) return;
    setError("");
    setPaying((p) => ({ ...p, [fineId]: true }));
    const prev = fines;
    const optimistic = fines.map((f) =>
      f.fine_id === fineId
        ? { ...f, paid_status: "paid", payment_date: new Date().toISOString() }
        : f
    );
    setFines(optimistic);

    try {
      // No backend call here. When backend is ready, insert POST /fines/pay with { fine_id: fineId }.
    } catch (e) {
      setFines(prev);
      setError("Payment failed. Reverted.");
    } finally {
      setPaying((p) => ({ ...p, [fineId]: false }));
    }
  };

  const handlePayAll = async () => {
    if (unpaidIds.length === 0) return;
    setError("");
    setPayAllLoading(true);
    const prev = fines;
    const stamp = new Date().toISOString();
    const optimistic = fines.map((f) =>
      String(f?.paid_status || "").toLowerCase() !== "paid"
        ? { ...f, paid_status: "paid", payment_date: stamp }
        : f
    );
    setFines(optimistic);

    try {
      // No backend call here. When backend is ready, call bulk endpoint or loop single payments.
    } catch (e) {
      setFines(prev);
      setError("Bulk payment failed. Reverted.");
    } finally {
      setPayAllLoading(false);
    }
  };

  const formatAmount = (amt) => {
    const n = Number(amt || 0);
    return n.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  };

  const formatDate = (d) => {
    if (!d) return "-";
    try {
      return new Date(d).toLocaleDateString();
    } catch {
      return String(d);
    }
  };

  if (loading) {
    return (
      <div className="p-6">
        <h1 className="text-2xl font-bold mb-4">Fines</h1>
        <div>Loading fines...</div>
      </div>
    );
  }

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Fines</h1>

      {error ? (
        <div className="mb-4 p-3 rounded bg-red-100 text-red-700">{error}</div>
      ) : null}

      <div className="flex flex-wrap items-center justify-between mb-4 gap-2">
        <div className="text-lg">
          Outstanding total: <span className="font-semibold">KSh {formatAmount(outstandingTotal)}</span>
        </div>
        <div className="flex gap-2">
          <button
            className="px-4 py-2 rounded bg-gray-200 hover:bg-gray-300"
            onClick={loadFines}
            disabled={loading}
            title="Reload fines"
          >
            Refresh
          </button>
          <button
            className="px-4 py-2 rounded bg-blue-600 text-white disabled:opacity-50"
            onClick={handlePayAll}
            disabled={payAllLoading || unpaidIds.length === 0}
            title={unpaidIds.length === 0 ? "No outstanding fines" : "Pay all outstanding fines"}
          >
            {payAllLoading ? "Processing..." : `Pay All (${unpaidIds.length})`}
          </button>
        </div>
      </div>

      {fines.length === 0 ? (
        <div className="p-6 rounded border border-gray-200 bg-white">
          <div className="text-gray-600">No fines to display.</div>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full bg-white border border-gray-200 rounded">
            <thead className="bg-gray-50">
              <tr>
                <th className="text-left p-3 border-b">Book</th>
                <th className="text-right p-3 border-b">Amount</th>
                <th className="text-left p-3 border-b">Status</th>
                <th className="text-left p-3 border-b">Payment Date</th>
                <th className="text-left p-3 border-b">Action</th>
              </tr>
            </thead>
            <tbody>
              {fines.map((f) => {
                const id = f.fine_id;
                const isPaid = String(f?.paid_status || "").toLowerCase() === "paid";
                const bookName = f?.title || f?.book_title || `Fine ${id}`;
                return (
                  <tr key={id} className="hover:bg-gray-50">
                    <td className="p-3 border-b">
                      <div className="font-medium">{bookName}</div>
                      <div className="text-xs text-gray-500">{id ? `Fine ID: ${id}` : null}</div>
                    </td>
                    <td className="p-3 border-b text-right">KSh {formatAmount(f?.amount)}</td>
                    <td className="p-3 border-b">
                      <span
                        className={
                          "px-2 py-1 text-xs rounded " +
                          (isPaid ? "bg-green-100 text-green-700" : "bg-yellow-100 text-yellow-700")
                        }
                      >
                        {isPaid ? "Paid" : "Unpaid"}
                      </span>
                    </td>
                    <td className="p-3 border-b">{isPaid ? formatDate(f?.payment_date) : "-"}</td>
                    <td className="p-3 border-b">
                      <button
                        className="px-3 py-1 rounded bg-emerald-600 text-white disabled:opacity-50"
                        onClick={() => handlePay(id)}
                        disabled={isPaid || paying[id]}
                      >
                        {isPaid ? "Paid" : paying[id] ? "Paying..." : "Pay"}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default Fines;
