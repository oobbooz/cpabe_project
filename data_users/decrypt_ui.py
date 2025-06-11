import tkinter as tk
from tkinter import ttk, messagebox
from document import DocumentUI
from a_cpabe import get_documents_by_type_and_department


class DecryptUI:
    def __init__(self, master, id_token):
        self.root = master 
        self.root.title("Decrypt Document")
        self.root.geometry("900x700")
        self.master = master
        self.master.title("📤 Giải mã")
        self.id_token = id_token or ""
        self.type_var = tk.StringVar(value='')
        self.department_var = tk.StringVar(value='')
        self.selected_doc_id = None

        self.departments = ["IT", "SALES", "HR", "FINANCE"]

        self.create_widgets()


    def create_widgets(self):
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Select Document Type:", font=("Segoe UI", 12)).pack(anchor=tk.W, pady=(0,5))
        self.type_combo = ttk.Combobox(frame, textvariable=self.type_var, values=["internal", "external"], state="readonly")
        self.type_combo.pack(fill=tk.X)
        self.type_combo.set('')  
        self.type_combo.bind("<<ComboboxSelected>>", self.on_type_selected)

        self.dept_label = ttk.Label(frame, text="Select Department:", font=("Segoe UI", 12))
        self.dept_combo = ttk.Combobox(frame, textvariable=self.department_var, values=self.departments, state="readonly")
        self.dept_combo.bind("<<ComboboxSelected>>", self.on_department_selected)

        ttk.Label(frame, text="Documents:", font=("Segoe UI", 12)).pack(anchor=tk.W, pady=(20,5))
        self.docs_listbox = tk.Listbox(frame, height=10)
        self.docs_listbox.pack(fill=tk.BOTH, expand=True)
        self.docs_listbox.bind("<<ListboxSelect>>", self.on_doc_selected)

    def on_type_selected(self, event=None):
        doc_type = self.type_var.get()
        self.docs_listbox.delete(0, tk.END)
        self.selected_doc_id = None

        if doc_type == "internal":
            self.dept_label.pack(anchor=tk.W, pady=(10, 5))
            self.dept_combo.pack(fill=tk.X)
            self.department_var.set('')
        else:
            self.dept_label.pack_forget()
            self.dept_combo.pack_forget()
            docs = get_documents_by_type_and_department(doc_type)
            self.fill_documents_list(docs)

    def on_department_selected(self, event=None):
        doc_type = self.type_var.get()
        department = self.department_var.get()
        self.docs_listbox.delete(0, tk.END)
        self.selected_doc_id = None

        if doc_type == "internal" and department:
            docs = get_documents_by_type_and_department(doc_type, department)
            self.fill_documents_list(docs)

    def fill_documents_list(self, docs):
        for doc in docs:
            display_name = f"{doc['name']} (Dept: {doc.get('department') or 'N/A'})"
            self.docs_listbox.insert(tk.END, display_name)
        self.docs = docs 
    def on_doc_selected(self, event=None):
        selection = self.docs_listbox.curselection()
        if not selection:
            return
        index = selection[0]
        doc = self.docs[index]
        self.selected_doc_id = doc["id"]
        
        messagebox.showinfo("Document Selected", f"Selected Document ID: {self.selected_doc_id}")

        new_window = tk.Toplevel(self.root)
        DocumentUI(new_window, self.id_token, self.selected_doc_id)

def run_DecryptUI(id_token):
    root = tk.Tk()
    app = DecryptUI(root, id_token)
    root.mainloop()

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        token = sys.argv[1]
    else:
        token = ""

    if not token or token == "...":
        print("Vui lòng cung cấp token hợp lệ.")
        sys.exit(1)

    run_DecryptUI(token)