#1.源目ip也添加下拉框，2.规则调用deepseek的api做出解释，3.在筛选字段后，在点击上半部分规则与解析后的不对应
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import re
import tkinter.font as tkFont
import requests


class RuleParser:
    @staticmethod
    def parse_rule(rule_str):
        """将 Suricata 规则解析为结构化字典"""
        pattern = r"""
            ^(?P<action>\w+)\s+
            (?P<protocol>\w+)\s+
            (?P<src_ip>[\$\w]+)\s+
            (?P<src_port>[\w]+)\s+
            ->\s+
            (?P<dst_ip>[\$\w]+)\s+
            (?P<dst_port>[\w]+)\s*
            \((?P<options>.+)\)$
        """
        match = re.match(pattern, rule_str.strip(), re.VERBOSE)
        if not match:
            return None

        rule = match.groupdict()
        options = {}

        # 改进选项解析，处理转义引号
        option_pattern = r'(\w+):(?:"((?:\\"|[^"])*)"|([^;]+))'
        for key, quoted_val, plain_val in re.findall(option_pattern, rule["options"]):
            value = quoted_val.replace(r'\"', '"') if quoted_val else plain_val.strip()
            options[key] = value

        rule["options"] = options
        return rule

    @staticmethod
    def generate_rule_str(rule):
        """将结构化规则转换为规则字符串"""
        options = []
        for k, v in rule["options"].items():
            if any(c in str(v) for c in ['"', ';', ' ']):
                v_escaped = str(v).replace('"', r'\"')
                options.append(f'{k}:"{v_escaped}"')
            else:
                options.append(f'{k}:{v}')
        options_str = '; '.join(options)
        return (f"{rule['action']} {rule['protocol']} {rule['src_ip']} {rule['src_port']} -> "
                f"{rule['dst_ip']} {rule['dst_port']} ({options_str};)")


class EditDialog(tk.Toplevel):
    """规则编辑对话框"""
    def __init__(self, parent, rule, is_new=False):
        super().__init__(parent)
        self.parent = parent
        self.rule = rule
        self.is_new = is_new
        self.result = None
        
        self.title("Edit Rule" if not is_new else "Add New Rule")
        self.build_ui()
        self.grab_set()
        self.transient(parent)

    def build_ui(self):
        """构建对话框界面"""
        main_frame = ttk.Frame(self)
        main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # 预定义IP选项
        ip_options = ['$HOME_NET', '$EXTERNAL_NET', 'any', '[IP地址]']
        
        # 修改后的字段配置
        fields = [
            ('action', 'Action:', 'combobox', ['alert', 'drop', 'pass']),
            ('protocol', 'Protocol:', 'combobox', ['tcp', 'udp', 'icmp']),
            ('src_ip', 'Source IP:', 'combobox', ip_options),
            ('src_port', 'Source Port:', 'entry'),
            ('dst_ip', 'Destination IP:', 'combobox', ip_options),
            ('dst_port', 'Destination Port:', 'entry')
        ]
        
        self.widgets = {}
        for row, (field, label, widget_type, *rest) in enumerate(fields):
            ttk.Label(main_frame, text=label).grid(row=row, column=0, sticky=tk.W, pady=2)
            if widget_type == 'combobox':
                var = tk.StringVar(value=self.rule.get(field, ''))
                cb = ttk.Combobox(main_frame, textvariable=var, values=rest[0])
                cb.grid(row=row, column=1, sticky=tk.EW, padx=5)
                self.widgets[field] = var
            else:
                var = tk.StringVar(value=self.rule.get(field, ''))
                entry = ttk.Entry(main_frame, textvariable=var)
                entry.grid(row=row, column=1, sticky=tk.EW, padx=5)
                self.widgets[field] = var

        # 选项字段
        ttk.Label(main_frame, text="Options:").grid(row=len(fields), column=0, sticky=tk.W, pady=5)
        self.options_text = tk.Text(main_frame, height=8, width=40)
        self.options_text.grid(row=len(fields) + 1, column=0, columnspan=2, sticky=tk.EW)
        
        # 加载现有选项
        options_str = '\n'.join([f"{k}:{v}" for k, v in self.rule['options'].items()])
        self.options_text.insert(tk.END, options_str)

        # 按钮区域
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=len(fields) + 2, column=0, columnspan=2, pady=10)
        ttk.Button(btn_frame, text="Save", command=self.on_save).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.destroy).pack(side=tk.RIGHT)

    def on_save(self):
        """保存编辑结果"""
        # 更新基本字段
        new_rule = {
            'action': self.widgets['action'].get(),
            'protocol': self.widgets['protocol'].get(),
            'src_ip': self.widgets['src_ip'].get(),
            'src_port': self.widgets['src_port'].get(),
            'dst_ip': self.widgets['dst_ip'].get(),
            'dst_port': self.widgets['dst_port'].get(),
            'options': {}
        }

        # 解析选项
        options = {}
        for line in self.options_text.get('1.0', tk.END).strip().split('\n'):
            if ':' in line:
                key, val = line.split(':', 1)
                options[key.strip()] = val.strip()
        
        # 验证必要字段
        if not new_rule['action']:
            messagebox.showerror("Error", "Action field is required!")
            return
        if 'sid' not in options:
            messagebox.showerror("Error", "SID option is required!")
            return
        if not options['sid'].isdigit():
            messagebox.showerror("Error", "SID must be a number!")
            return
        
        # 检查SID唯一性
        if self.is_new and not self.parent.is_sid_unique(options['sid']):
            messagebox.showerror("Error", "SID must be unique!")
            return
        
        new_rule['options'] = options
        self.result = new_rule
        self.destroy()


class RuleManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Suricata Rule Manager")
        self.rules = []  # 存储结构化规则数据
        self.current_displayed_indices = []  # 添加当前显示索引列表

        # 创建菜单栏
        self.create_menu()
        # 控制按钮区域
        self.control_frame = ttk.Frame(root)
        self.control_frame.pack(fill=tk.X)
        # 添加控制按钮
        self.create_control_buttons()
        # 主界面布局
        self.main_paned = ttk.PanedWindow(root, orient=tk.VERTICAL)
        self.main_paned.pack(fill=tk.BOTH, expand=True)
        # 规则表格区域
        self.create_rule_tree()
        # 规则详情区域
        self.create_detail_area()
        
        # 初始化 sash 位置
        self.main_paned.sashpos(0, int(self.root.winfo_height()*0.6))

    def create_menu(self):
        """创建菜单栏"""
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)

        # 文件菜单
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.file_menu.add_command(label="Open Rules", command=self.open_rules)
        self.file_menu.add_command(label="Save Rules", command=self.save_rules)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self.root.quit)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)

    def create_control_buttons(self):
        """创建控制按钮区域"""
        ttk.Button(self.control_frame, text="Add", command=self.add_rule).pack(side=tk.LEFT, padx=2)
        ttk.Button(self.control_frame, text="Delete", command=self.delete_rule).pack(side=tk.LEFT, padx=2)
        ttk.Button(self.control_frame, text="Edit", command=self.edit_rule).pack(side=tk.LEFT, padx=2)

        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(self.control_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.RIGHT, padx=2)
        ttk.Button(self.control_frame, text="Search", command=self.search_rules).pack(side=tk.RIGHT)

    def create_rule_tree(self):
        """创建规则表格"""
        self.tree_frame = ttk.Frame(self.main_paned)
        self.tree = ttk.Treeview(self.tree_frame, columns=("message", "sid", "classtype"), show="headings")

        # 配置表格列
        columns = [
            ("message", "Message", 250),
            ("sid", "SID", 80),
            ("classtype", "Classtype", 100)
        ]
        for col_id, col_text, width in columns:
            self.tree.heading(col_id, text=col_text)
            self.tree.column(col_id, width=width, anchor=tk.W)

        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind('<<TreeviewSelect>>', self.show_rule_details)
        self.main_paned.add(self.tree_frame)

    def create_detail_area(self):
        """创建规则详情区域"""
        self.detail_frame = ttk.Frame(self.main_paned)
        self.detail_text = tk.Text(self.detail_frame, wrap=tk.WORD, height=8, font=tkFont.Font(size=12))
        self.detail_text.pack(fill=tk.BOTH, expand=True)
        self.main_paned.add(self.detail_frame)

    def open_rules(self):
        """打开规则文件并解析"""
        file_path = filedialog.askopenfilename(filetypes=[("Suricata Rules", "*.rules")])
        if not file_path:
            return

        self.rules.clear()
        self.tree.delete(*self.tree.get_children())
        self.current_displayed_indices.clear()  # 清空当前显示索引

        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    rule = RuleParser.parse_rule(line)
                    if rule:
                        self.rules.append(rule)
                        self.current_displayed_indices.append(len(self.rules) - 1)  # 记录原始索引
                        self._add_rule_to_tree(rule)

    def save_rules(self):
        """保存规则到文件"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".rules",
            filetypes=[("Suricata Rules", "*.rules")]
        )
        if not file_path:
            return

        with open(file_path, "w") as f:
            for rule in self.rules:
                options_str = "; ".join([f'{k}:"{v}"' if " " in v else f'{k}:{v}' for k, v in rule["options"].items()])
                rule_str = (
                    f"{rule['action']} {rule['protocol']} {rule['src_ip']} {rule['src_port']} -> "
                    f"{rule['dst_ip']} {rule['dst_port']} ({options_str};)\n"
                )
                f.write(rule_str)

    def _add_rule_to_tree(self, rule):
        """添加规则到表格视图"""
        self.tree.insert("", tk.END, values=(
            rule["options"].get("msg", ""),
            rule["options"].get("sid", ""),
            rule["options"].get("classtype", "")
        ))

    def show_rule_details(self, event):
        """显示选中规则的详细信息"""
        selected = self.tree.selection()
        if not selected:
            return

        # 通过当前显示索引获取实际规则索引
        try:
            tree_index = self.tree.index(selected[0])
            original_index = self.current_displayed_indices[tree_index]
            rule = self.rules[original_index]
        except IndexError:
            return

        details = [
            f"Action: {rule['action']}",
            f"Protocol: {rule['protocol']}",
            f"Source: {rule['src_ip']}:{rule['src_port']}",
            f"Destination: {rule['dst_ip']}:{rule['dst_port']}",
            "\nOptions:"
        ]

        for k, v in rule["options"].items():
            details.append(f"  {k}: {v}")

        self.detail_text.delete(1.0, tk.END)
        self.detail_text.insert(tk.END, "\n".join(details))

    def add_rule(self):
        """添加新规则"""
        new_rule = {
            'action': 'alert',
            'protocol': 'tcp',
            'src_ip': '$HOME_NET',
            'src_port': 'any',
            'dst_ip': '$EXTERNAL_NET',
            'dst_port': 'any',
            'options': {'msg': 'New rule', 'sid': '1000001'}
        }
        dlg = EditDialog(self.root, new_rule, is_new=True)
        self.root.wait_window(dlg)
        
        if dlg.result:
            self.rules.append(dlg.result)
            self.current_displayed_indices.append(len(self.rules) - 1)  # 记录原始索引
            self._add_rule_to_tree(dlg.result)

    def edit_rule(self):
        """编辑现有规则"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a rule to edit")
            return
        
        index = self.tree.index(selected[0])
        dlg = EditDialog(self.root, self.rules[index])
        self.root.wait_window(dlg)
        
        if dlg.result:
            self.rules[index] = dlg.result
            self.tree.item(selected[0], values=(
                dlg.result['options'].get('msg', ''),
                dlg.result['options'].get('sid', ''),
                dlg.result['options'].get('classtype', '')
            ))
            self.show_rule_details(None)  # 刷新详情显示

    def delete_rule(self):
        """删除选中的规则"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a rule to delete")
            return

        rule_idx = self.tree.index(selected[0])
        original_index = self.current_displayed_indices[rule_idx]  # 获取原始索引
        del self.rules[original_index]  # 从规则列表中删除选中的规则
        self.tree.delete(selected[0])  # 从树视图中删除选中的项
        self.current_displayed_indices.pop(rule_idx)  # 从当前显示索引中删除

    def search_rules(self):
        """搜索规则"""
        query = self.search_var.get().lower()
        self.tree.delete(*self.tree.get_children())
        self.current_displayed_indices.clear()  # 清空当前显示索引

        for idx, rule in enumerate(self.rules):
            if (query in rule['action'].lower() or
                query in rule['protocol'].lower() or
                any(query in str(v).lower() for v in rule['options'].values())):
                self.current_displayed_indices.append(idx)  # 记录原始索引
                self.tree.insert('', tk.END, values=(
                    rule['options'].get('msg', ''),
                    rule['options'].get('sid', ''),
                    rule['options'].get('classtype', '')
                ))

    def is_sid_unique(self, sid):
        """检查SID是否唯一"""
        return all(str(rule['options'].get('sid', '')) != sid for rule in self.rules)


if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("800x600")
    app = RuleManager(root)
    root.mainloop()