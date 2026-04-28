function FoundationToggle({ value, onChange }) {
  return (
    <div className="flex flex-wrap items-center gap-3 rounded-xl border border-slate-200 bg-white p-3 shadow-sm">
      <span className="text-sm font-semibold text-slate-700">Foundation:</span>
      {['AES', 'DLP'].map((option) => (
        <button
          key={option}
          onClick={() => onChange(option)}
          className={`rounded-lg border px-3 py-1.5 text-sm font-medium transition ${
            value === option
              ? 'border-blue-600 bg-blue-600 text-white'
              : 'border-slate-300 bg-white text-slate-700 hover:bg-slate-50'
          }`}
        >
          {option}
        </button>
      ))}
    </div>
  )
}

export default FoundationToggle
