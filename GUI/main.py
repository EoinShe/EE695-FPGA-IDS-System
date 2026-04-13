import sys
from pathlib import Path

from PySide6.QtCore import Qt, QRectF
from PySide6.QtGui import QBrush, QColor, QFont, QPen, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFormLayout,
    QGraphicsEllipseItem,
    QGraphicsLineItem,
    QGraphicsPixmapItem,
    QGraphicsScene,
    QGraphicsSimpleTextItem,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
    QPlainTextEdit,
)

from topology import NODES, Node
from packet_builder import ScenarioItem, generate_header_text


class ClickableNodeItem(QGraphicsPixmapItem):
    def __init__(self, node: Node, main_window, size: int = 64):
        super().__init__()
        self.node = node
        self.main_window = main_window

        icon_path = self.get_icon_path(node)
        pixmap = QPixmap(icon_path)

        if pixmap.isNull():
            print(f"Failed to load image: {icon_path}")
            pixmap = QPixmap(size, size)
            pixmap.fill(QColor("#CCCCCC"))

        pixmap = pixmap.scaled(
            size,
            size,
            Qt.KeepAspectRatio,
            Qt.SmoothTransformation,
        )
        self.setPixmap(pixmap)

        self.setPos(node.x - pixmap.width() / 2, node.y - pixmap.height() / 2)
        self.setAcceptedMouseButtons(Qt.LeftButton)

        self.selection_ring_1 = QGraphicsEllipseItem(
            -6, -6, pixmap.width() + 12, pixmap.height() + 12, self
        )
        self.selection_ring_1.setPen(QPen(QColor("#FF8C00"), 3))
        self.selection_ring_1.setBrush(Qt.NoBrush)
        self.selection_ring_1.setVisible(False)

        self.selection_ring_2 = QGraphicsEllipseItem(
            -12, -12, pixmap.width() + 24, pixmap.height() + 24, self
        )
        self.selection_ring_2.setPen(QPen(QColor("#FFA500"), 2))
        self.selection_ring_2.setBrush(Qt.NoBrush)
        self.selection_ring_2.setVisible(False)

        label = QGraphicsSimpleTextItem(node.name)
        label.setFont(QFont("Arial", 10))
        label.setBrush(QBrush(QColor("#000000")))
        label.setParentItem(self)
        label.setPos(0, pixmap.height() + 6)

    def get_icon_path(self, node: Node):
        if node.kind == "core":
            return "Images/Network-Switch.png"
        if node.kind == "fpga":
            return "Images/FPGA.png"
        if "Server" in node.name:
            return "Images/Server.png"
        return "Images/VM.png"

    def set_selected_visual(self, selected: bool):
        self.selection_ring_1.setVisible(selected)
        self.selection_ring_2.setVisible(selected)

    def mousePressEvent(self, event):
        self.main_window.on_node_selected(self.node)
        super().mousePressEvent(event)


class TopologyView(QGraphicsView):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.scene_obj = QGraphicsScene()
        self.scene_obj.setSceneRect(QRectF(-380, -260, 760, 680))
        self.scene_obj.setBackgroundBrush(QColor("#FFFFFF"))
        self.setScene(self.scene_obj)
        self.setMinimumWidth(760)

        self.lines = {}
        self.node_items = {}

        # Persistent scenario state
        self.source_nodes = set()
        self.dest_nodes = set()

        # Temporary current selection state
        self.selected_source_node = None
        self.selected_dest_node = None

        self.draw_topology()

    def draw_topology(self):
        self.scene_obj.clear()
        self.lines.clear()
        self.node_items.clear()

        core = next(n for n in NODES if n.kind == "core")
        others = [n for n in NODES if n != core]

        for node in others:
            x1, y1 = core.x, core.y
            x2, y2 = node.x, node.y

            line = QGraphicsLineItem(x1, y1, x2, y2)
            line.setPen(QPen(QColor("#87CEFA"), 2))
            self.scene_obj.addItem(line)
            self.lines[node.name] = line

        for node in NODES:
            item = ClickableNodeItem(node, self.main_window)
            self.scene_obj.addItem(item)
            self.node_items[node.name] = item

    def update_line_colors(self):
        for node_name, line in self.lines.items():
            # Priority:
            # 1. Scenario destination = red
            # 2. Scenario source = yellow
            # 3. Currently selected destination = red
            # 4. Currently selected source = yellow
            # 5. Default = blue
            if node_name in self.dest_nodes:
                line.setPen(QPen(QColor("#FF0000"), 3))
            elif node_name in self.source_nodes:
                line.setPen(QPen(QColor("#FFD700"), 3))
            elif node_name == self.selected_dest_node:
                line.setPen(QPen(QColor("#FF0000"), 3))
            elif node_name == self.selected_source_node:
                line.setPen(QPen(QColor("#FFD700"), 3))
            else:
                line.setPen(QPen(QColor("#87FA9A"), 2))

    def mark_source_node(self, node_name: str):
        self.source_nodes.add(node_name)
        self.update_line_colors()

    def mark_dest_node(self, node_name: str):
        self.dest_nodes.add(node_name)
        self.update_line_colors()

    def reset_lines(self):
        self.source_nodes.clear()
        self.dest_nodes.clear()
        self.selected_source_node = None
        self.selected_dest_node = None
        self.update_line_colors()

    def set_selected_nodes(self, source_name: str | None, dest_name: str | None):
        self.selected_source_node = source_name
        self.selected_dest_node = dest_name

        selected_names = set()
        if source_name:
            selected_names.add(source_name)
        if dest_name:
            selected_names.add(dest_name)

        for name, item in self.node_items.items():
            item.set_selected_visual(name in selected_names)

        self.update_line_colors()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IDS Attack Scenario Builder")
        self.resize(1300, 800)

        self.source_node = None
        self.dest_node = None
        self.selection_mode = "source"
        self.scenario_items = []
        self.preview_window = None

        central = QWidget()
        self.setCentralWidget(central)

        layout = QHBoxLayout(central)

        # -----------------------------
        # Left panel: topology card
        # -----------------------------
        self.topology_view = TopologyView(self)

        topology_container = QWidget()
        topology_container.setStyleSheet("""
        QWidget {
            background-color: #f5f5f5;
            border: 1px solid #cccccc;
            border-radius: 8px;
        }
        """)

        topology_layout = QVBoxLayout(topology_container)
        topology_layout.setContentsMargins(10, 10, 10, 10)

        title_label = QLabel("EE695 Project Topology")
        title_label.setStyleSheet("""
        QLabel {
            font-size: 18px;
            font-weight: bold;
            color: #333333;
            padding: 4px;
            border: none;
            background-color: transparent;
        }
        """)
        topology_layout.addWidget(title_label)

        divider = QWidget()
        divider.setFixedHeight(1)
        divider.setStyleSheet("background-color: #cccccc; border: none;")
        topology_layout.addWidget(divider)

        self.topology_view.setStyleSheet("border: none; background: white;")
        topology_layout.addWidget(self.topology_view)

        layout.addWidget(topology_container, 2)

        # -----------------------------
        # Right panel: controls
        # -----------------------------
        side_widget = QWidget()
        side_widget.setStyleSheet("""
        QWidget {
            background-color: #1b1b1b;
            color: #f2f2f2;
            font-size: 14px;
        }

        QLabel {
            background-color: transparent;
            color: #f2f2f2;
            border: none;
        }

        QPushButton {
            background-color: #2a2a2a;
            color: #ffffff;
            border: 1px solid #555555;
            padding: 8px;
            border-radius: 6px;
        }

        QPushButton:hover {
            background-color: #3a3a3a;
        }

        QListWidget, QSpinBox {
            background-color: #222222;
            color: #ffffff;
            border: 1px solid #555555;
            border-radius: 4px;
        }

        QAbstractSpinBox {
            background-color: #222222;
            color: #ffffff;
            border: 1px solid #555555;
            border-radius: 4px;
        }

        QScrollBar:vertical {
            background: #1b1b1b;
            width: 12px;
        }

        QScrollBar::handle:vertical {
            background: #666666;
            min-height: 20px;
        }
        """)
        side_layout = QVBoxLayout(side_widget)
        layout.addWidget(side_widget, 1)

        self.selected_label = QLabel("Src: None  →  Dst: None")
        self.selected_label.setWordWrap(True)
        side_layout.addWidget(self.selected_label)

        mode_label = QLabel("Selection Mode:")
        side_layout.addWidget(mode_label)

        self.src_button = QPushButton("Pick Source")
        self.dst_button = QPushButton("Pick Destination")

        self.src_button.clicked.connect(lambda: self.set_selection_mode("source"))
        self.dst_button.clicked.connect(lambda: self.set_selection_mode("destination"))

        side_layout.addWidget(self.src_button)
        side_layout.addWidget(self.dst_button)

        self.update_mode_buttons()

        form = QFormLayout()

        self.attack_list = QListWidget()
        self.attack_list.setMaximumHeight(220)

        attacks = [
            "Normal",
            "SYN Flood",
            "UDP Flood",
            "ICMP Flood",
            "Xmas Scan",
            "Null Scan",
        ]

        for attack in attacks:
            item = QListWidgetItem(attack)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Unchecked)
            self.attack_list.addItem(item)

        self.packet_spin = QSpinBox()
        self.packet_spin.setRange(1, 10000)
        self.packet_spin.setValue(10)

        form.addRow("Attack Type(s):", self.attack_list)
        form.addRow("Packet Count:", self.packet_spin)
        side_layout.addLayout(form)

        add_btn = QPushButton("Add to Scenario")
        add_btn.clicked.connect(self.add_to_scenario)
        side_layout.addWidget(add_btn)

        side_layout.addWidget(QLabel("Scenario Items:"))

        self.list_widget = QListWidget()
        side_layout.addWidget(self.list_widget)

        gen_btn = QPushButton("Generate Header")
        gen_btn.clicked.connect(self.generate_header)
        side_layout.addWidget(gen_btn)

        preview_btn = QPushButton("Preview Header")
        preview_btn.clicked.connect(self.preview_header)
        side_layout.addWidget(preview_btn)

        clear_btn = QPushButton("Clear Scenario")
        clear_btn.clicked.connect(self.clear_scenario)
        side_layout.addWidget(clear_btn)

        side_layout.addStretch()

    def set_selection_mode(self, mode: str):
        self.selection_mode = mode
        self.update_mode_buttons()

    def update_mode_buttons(self):
        active_style = """
        QPushButton {
            background-color: #c48b00;
            color: black;
            border: 1px solid #e0aa1a;
            padding: 8px;
            border-radius: 6px;
            font-weight: bold;
        }
        """
        normal_style = """
        QPushButton {
            background-color: #2a2a2a;
            color: white;
            border: 1px solid #555555;
            padding: 8px;
            border-radius: 6px;
        }
        QPushButton:hover {
            background-color: #3a3a3a;
        }
        """

        if self.selection_mode == "source":
            self.src_button.setStyleSheet(active_style)
            self.dst_button.setStyleSheet(normal_style)
        else:
            self.src_button.setStyleSheet(normal_style)
            self.dst_button.setStyleSheet(active_style)

    def refresh_selected_display(self):
        src = self.source_node.name if self.source_node else "None"
        dst = self.dest_node.name if self.dest_node else "None"
        self.selected_label.setText(f"Src: {src}  →  Dst: {dst}")

        src_name = self.source_node.name if self.source_node else None
        dst_name = self.dest_node.name if self.dest_node else None
        self.topology_view.set_selected_nodes(src_name, dst_name)

    def on_node_selected(self, node: Node):
        if node.kind in ("core", "fpga"):
            self.selected_label.setText(f"{node.name} (not selectable)")
            return

        if self.selection_mode == "source":
            if self.source_node and self.source_node.name == node.name:
                self.source_node = None
            else:
                self.source_node = node
        else:
            if self.dest_node and self.dest_node.name == node.name:
                self.dest_node = None
            else:
                self.dest_node = node

        self.refresh_selected_display()

    def add_to_scenario(self):
        if not self.source_node or not self.dest_node:
            QMessageBox.warning(self, "Error", "Select both source and destination.")
            return

        selected_attacks = []
        for i in range(self.attack_list.count()):
            item = self.attack_list.item(i)
            if item.checkState() == Qt.Checked:
                selected_attacks.append(item.text())

        if not selected_attacks:
            QMessageBox.warning(self, "Error", "Select at least one attack type.")
            return

        count = self.packet_spin.value()

        for attack in selected_attacks:
            scenario_item = ScenarioItem(
                source_name=self.source_node.name,
                source_ip=self.source_node.ip,
                dest_name=self.dest_node.name,
                dest_ip=self.dest_node.ip,
                attack_type=attack,
                packet_count=count,
            )
            self.scenario_items.append(scenario_item)

            display = (
                f"{self.source_node.name} → {self.dest_node.name} | "
                f"{attack} x{count}"
            )
            self.list_widget.addItem(QListWidgetItem(display))

        # Source path = yellow, destination path = red
        self.topology_view.mark_source_node(self.source_node.name)
        self.topology_view.mark_dest_node(self.dest_node.name)

    def generate_header(self):
        if not self.scenario_items:
            QMessageBox.warning(self, "Error", "No scenario items to generate.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Header File",
            "ids_test_packets.h",
            "Header Files (*.h)",
        )
        if not path:
            return

        text = generate_header_text(self.scenario_items)
        Path(path).write_text(text, encoding="utf-8")

        QMessageBox.information(self, "Done", f"Header file generated:\n{path}")

    def preview_header(self):
        if not self.scenario_items:
            QMessageBox.warning(self, "Error", "No scenario items to preview.")
            return

        text = generate_header_text(self.scenario_items)

        preview = QWidget()
        preview.setWindowTitle("Header Preview")
        preview.resize(900, 650)

        layout = QVBoxLayout(preview)

        text_box = QPlainTextEdit()
        text_box.setPlainText(text)
        text_box.setReadOnly(True)
        text_box.setStyleSheet("""
        QPlainTextEdit {
            background-color: #1e1e1e;
            color: #00ffaa;
            font-family: Consolas;
            font-size: 12px;
            border: 1px solid #444444;
        }
        """)
        layout.addWidget(text_box)

        preview.show()
        self.preview_window = preview

    def clear_scenario(self):
        self.scenario_items.clear()
        self.list_widget.clear()
        self.topology_view.reset_lines()

        for i in range(self.attack_list.count()):
            self.attack_list.item(i).setCheckState(Qt.Unchecked)

        self.source_node = None
        self.dest_node = None
        self.selected_label.setText("Src: None  →  Dst: None")
        self.topology_view.set_selected_nodes(None, None)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())