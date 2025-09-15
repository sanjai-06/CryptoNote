import { useState } from "react";
import { createPortal } from "react-dom";

export default function CategoryManager({ categories, onCategoryCreated, onCategoryUpdated, onCategoryDeleted }) {
  const [showModal, setShowModal] = useState(false);
  const [editingCategory, setEditingCategory] = useState(null);
  const [form, setForm] = useState({ name: "", icon: "📁", color: "#8B5CF6" });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const commonIcons = ["📁", "👤", "💼", "👥", "💰", "🎮", "🏠", "🚗", "🏥", "🎓", "🛒", "✈️"];
  const commonColors = ["#8B5CF6", "#3B82F6", "#10B981", "#F59E0B", "#EF4444", "#8B5A2B", "#EC4899", "#6366F1"];

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!form.name.trim()) {
      setError("Category name is required");
      return;
    }

    setLoading(true);
    setError("");

    try {
      if (editingCategory) {
        await onCategoryUpdated(editingCategory._id, form);
      } else {
        await onCategoryCreated(form);
      }
      
      setForm({ name: "", icon: "📁", color: "#8B5CF6" });
      setEditingCategory(null);
      setShowModal(false);
    } catch (err) {
      setError(err.response?.data?.message || "Operation failed");
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = (category) => {
    setForm({
      name: category.name,
      icon: category.icon,
      color: category.color
    });
    setEditingCategory(category);
    setShowModal(true);
  };

  const handleDelete = async (categoryId) => {
    if (!window.confirm("Are you sure you want to delete this category? This action cannot be undone.")) {
      return;
    }

    try {
      await onCategoryDeleted(categoryId);
    } catch (err) {
      setError(err.response?.data?.message || "Failed to delete category");
    }
  };

  const resetForm = () => {
    setForm({ name: "", icon: "📁", color: "#8B5CF6" });
    setEditingCategory(null);
    setError("");
  };

  return (
    <div>
      <button
        onClick={() => setShowModal(true)}
        className="px-4 py-2 bg-purple-600/20 hover:bg-purple-600/30 border border-purple-600/30 rounded-lg text-purple-300 font-medium transition-all duration-200 flex items-center"
      >
        <span className="mr-2">➕</span> Manage Categories
      </button>

      {showModal && createPortal(
        <div
          className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-[9999] p-4"
          onClick={() => {
            setShowModal(false);
            resetForm();
          }}
        >
          <div
            className="bg-gray-900/95 backdrop-blur-lg border border-white/20 rounded-2xl p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-semibold text-white flex items-center">
                <span className="mr-2">🏷️</span> Manage Categories
              </h2>
              <button
                onClick={() => {
                  setShowModal(false);
                  resetForm();
                }}
                className="p-2 text-gray-400 hover:text-white transition-colors"
              >
                ✕
              </button>
            </div>

            {error && (
              <div className="mb-4 p-3 bg-red-500/20 border border-red-500/30 rounded-lg text-red-300">
                {error}
              </div>
            )}

            {/* Create/Edit Form */}
            <form onSubmit={handleSubmit} className="mb-6 p-4 bg-white/5 rounded-xl border border-white/10">
              <h3 className="text-lg font-medium text-white mb-4">
                {editingCategory ? "Edit Category" : "Create New Category"}
              </h3>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm text-gray-300 mb-2">Category Name</label>
                  <input
                    type="text"
                    value={form.name}
                    onChange={(e) => setForm({ ...form, name: e.target.value })}
                    className="w-full p-3 bg-white/5 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-purple-500/50"
                    placeholder="Enter category name"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm text-gray-300 mb-2">Icon</label>
                  <div className="grid grid-cols-6 gap-2 mb-3">
                    {commonIcons.map(icon => (
                      <button
                        key={icon}
                        type="button"
                        onClick={() => setForm({ ...form, icon })}
                        className={`p-3 rounded-lg text-xl transition-all ${
                          form.icon === icon 
                            ? 'bg-purple-600/30 border-2 border-purple-500' 
                            : 'bg-white/5 border border-white/20 hover:bg-white/10'
                        }`}
                      >
                        {icon}
                      </button>
                    ))}
                  </div>
                  <input
                    type="text"
                    value={form.icon}
                    onChange={(e) => setForm({ ...form, icon: e.target.value })}
                    className="w-full p-2 bg-white/5 border border-white/20 rounded-lg text-white text-center"
                    placeholder="Or enter custom emoji"
                  />
                </div>

                <div>
                  <label className="block text-sm text-gray-300 mb-2">Color</label>
                  <div className="grid grid-cols-8 gap-2 mb-3">
                    {commonColors.map(color => (
                      <button
                        key={color}
                        type="button"
                        onClick={() => setForm({ ...form, color })}
                        className={`w-8 h-8 rounded-lg transition-all ${
                          form.color === color ? 'ring-2 ring-white' : ''
                        }`}
                        style={{ backgroundColor: color }}
                      />
                    ))}
                  </div>
                  <input
                    type="color"
                    value={form.color}
                    onChange={(e) => setForm({ ...form, color: e.target.value })}
                    className="w-full h-10 bg-white/5 border border-white/20 rounded-lg"
                  />
                </div>
              </div>

              <div className="flex space-x-3 mt-6">
                <button
                  type="submit"
                  disabled={loading}
                  className="flex-1 py-3 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 rounded-xl text-white font-semibold transition-all duration-300 disabled:opacity-50"
                >
                  {loading ? "Saving..." : (editingCategory ? "Update Category" : "Create Category")}
                </button>
                {editingCategory && (
                  <button
                    type="button"
                    onClick={resetForm}
                    className="px-6 py-3 bg-gray-600/20 hover:bg-gray-600/30 border border-gray-600/30 rounded-xl text-gray-300 font-semibold transition-all duration-300"
                  >
                    Cancel
                  </button>
                )}
              </div>
            </form>

            {/* Categories List */}
            <div>
              <h3 className="text-lg font-medium text-white mb-4">Your Categories</h3>
              <div className="space-y-2">
                {categories.map(category => (
                  <div
                    key={category._id}
                    className="flex items-center justify-between p-3 bg-white/5 rounded-lg border border-white/10"
                  >
                    <div className="flex items-center">
                      <span className="text-xl mr-3">{category.icon}</span>
                      <span className="text-white font-medium">{category.name}</span>
                      <div
                        className="w-4 h-4 rounded-full ml-3"
                        style={{ backgroundColor: category.color }}
                      />
                    </div>
                    <div className="flex space-x-2">
                      <button
                        onClick={() => handleEdit(category)}
                        className="p-2 text-blue-400 hover:text-blue-300 transition-colors"
                        title="Edit category"
                      >
                        ✏️
                      </button>
                      <button
                        onClick={() => handleDelete(category._id)}
                        className="p-2 text-red-400 hover:text-red-300 transition-colors"
                        title="Delete category"
                      >
                        🗑️
                      </button>
                    </div>
                  </div>
                ))}
                {categories.length === 0 && (
                  <div className="text-center py-8 text-gray-400">
                    No categories yet. Create your first category above!
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>,
        document.body
      )}
    </div>
  );
}
