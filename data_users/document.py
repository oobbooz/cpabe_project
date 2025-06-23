import tkinter as tk
from tkinter import ttk, messagebox
import requests
import json
from decrypt import DecryptUI  


class DocumentUI:
    def __init__(self, master, id_token):
        self.root = master
        self.root.title("Decrypt Document")
        self.root.geometry("900x700")
        self.id_token = id_token or ""
        self.type_var = tk.StringVar()
        self.department_var = tk.StringVar()
        self.search_var = tk.StringVar()
        self.selected_doc_id = None
        self.docs = []        
        self.filtered_docs = [] 

        self.departments = ["IT", "SALES", "HR", "FINANCE"]
        self.search_var.trace_add("write", self.filter_documents)
        self.create_widgets()

    def create_widgets(self):
        self.root.configure(bg="#f0f4ff")

        title_label = tk.Label(self.root, text="Documents", font=("Segoe UI", 24, "bold"), bg="#f0f4ff", fg="#003366")
        title_label.pack(pady=(30, 10))

        frame = ttk.Frame(self.root, padding=20)
        frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=10)

        ttk.Label(frame, text="Select Document Type:", font=("Segoe UI", 12)).pack(anchor=tk.W, pady=(0, 5))
        self.type_combo = ttk.Combobox(frame, textvariable=self.type_var, values=["internal", "external"], state="readonly")
        self.type_combo.pack(fill=tk.X)
        self.type_combo.set('')
        self.type_combo.bind("<<ComboboxSelected>>", self.on_type_selected)

        self.dept_label = ttk.Label(frame, text="Select Department:", font=("Segoe UI", 12))
        self.dept_combo = ttk.Combobox(frame, textvariable=self.department_var, values=self.departments, state="readonly")
        self.dept_combo.bind("<<ComboboxSelected>>", self.on_department_selected)

        ttk.Label(frame, text="Documents:", font=("Segoe UI", 12)).pack(anchor=tk.W, pady=(20, 5))

        self.docs_listbox = tk.Listbox(
            frame,
            height=12,
            font=("Arial", 11),
            activestyle='dotbox',
            highlightcolor="#003366",
            selectbackground="#cce0ff"
        )
        self.docs_listbox.pack(fill=tk.BOTH, expand=True)
        self.docs_listbox.bind("<<ListboxSelect>>", self.on_doc_selected)

        ttk.Label(frame, text="Search:", font=("Segoe UI", 12)).pack(anchor=tk.W, pady=(15, 5))
        search_entry = ttk.Entry(frame, textvariable=self.search_var)
        search_entry.pack(fill=tk.X)

    def on_type_selected(self, event=None):
        doc_type = self.type_var.get()
        self.clear_documents()
        self.selected_doc_id = None

        if doc_type == "internal":
            self.dept_label.pack(anchor=tk.W, pady=(10, 5))
            self.dept_combo.pack(fill=tk.X)
            self.department_var.set('')
        else:
            self.dept_label.pack_forget()
            self.dept_combo.pack_forget()
            self.fetch_and_display_docs(doc_type)

    def on_department_selected(self, event=None):
        doc_type = self.type_var.get()
        department = self.department_var.get()
        self.clear_documents()
        self.selected_doc_id = None

        if doc_type == "internal" and department:
            self.fetch_and_display_docs(doc_type, department)

    def fetch_and_display_docs(self, doc_type, department=None):
        try:
            docs = get_documents_by_type_and_department(self.id_token, doc_type, department)
            self.docs = docs
            self.filter_documents()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch documents:\n{e}")

    def clear_documents(self):
        self.docs_listbox.delete(0, tk.END)
        self.docs = []
        self.filtered_docs = []

    def filter_documents(self, *args):
        keyword = self.search_var.get().lower()
        self.docs_listbox.delete(0, tk.END)
        self.filtered_docs = []

        for doc in self.docs:
            name = doc.get("doc_name", "").lower()
            if keyword in name:
                self.filtered_docs.append(doc)
                self.docs_listbox.insert(tk.END, doc.get("doc_name", "Unnamed Document"))

    def on_doc_selected(self, event=None):
        selection = self.docs_listbox.curselection()
        if not selection:
            return
        index = selection[0]
        doc = self.filtered_docs[index]
        self.selected_doc_name = doc["doc_name"]
        self.selected_doc_id = doc["doc_id"]

        messagebox.showinfo("Document Selected", f"Selected Document: {self.selected_doc_name}")
        new_window = tk.Toplevel(self.root)
        department = self.department_var.get()
        DecryptUI(new_window, self.id_token, self.selected_doc_id, department)

def get_documents_by_type_and_department(id_token, doc_type, department=None):
    headers = {
        "Authorization": f"Bearer {id_token.strip()}",
        "Content-Type": "application/json"
    }

    resource = {"type": doc_type}
    if department:
        resource["department"] = department

    payload = {
        "action": "read",
        "resource": resource
    }

    try:
        res = requests.post("https://handle-request-itz4xkhbza-as.a.run.app", headers=headers, data=json.dumps(payload))
        if res.status_code == 200:
            return res.json()
        else:
            raise Exception(f"Error: {res.status_code} - {res.text}")
    except Exception as e:
        raise


def run_DocumentUI(id_token):
    root = tk.Tk()
    app = DocumentUI(root, id_token)
    root.mainloop()


if __name__ == "__main__":
    import sys
    token = sys.argv[1] if len(sys.argv) > 1 else ""
    if not token or len(token.split(".")) != 3:
        print("Please provide a valid JWT token (with 3 segments).")
        sys.exit(1)
    run_DocumentUI(token)
