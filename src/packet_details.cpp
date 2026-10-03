#include "packet_details.hpp"
#include "packet_table_model.hpp"

#include <QFontDatabase>
#include <QPlainTextEdit>
#include <QSplitter>
#include <QTextCursor>
#include <QTextEdit>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <algorithm>

namespace deep_wire {
namespace {

constexpr int offset_role = Qt::UserRole;
constexpr int length_role = Qt::UserRole + 1;

void set_range(QTreeWidgetItem* item, const std::size_t offset, const std::size_t length)
{
    item->setData(0, offset_role, QVariant::fromValue(static_cast<qulonglong>(offset)));
    item->setData(0, length_role, QVariant::fromValue(static_cast<qulonglong>(length)));
}

void add_field(QTreeWidgetItem* parent, const QString& name, const QString& value)
{
    new QTreeWidgetItem{parent, QStringList{name, value}};
}

} // namespace

PacketDetails::PacketDetails(QWidget* parent) : QWidget{parent}
{
    auto* layout = new QVBoxLayout{this};
    layout->setContentsMargins(0, 0, 0, 0);
    auto* splitter = new QSplitter{Qt::Horizontal, this};
    layers_ = new QTreeWidget{splitter};
    layers_->setObjectName("packetLayers");
    layers_->setHeaderLabels({"Layer / field", "Value"});
    layers_->setColumnWidth(0, 230);
    layers_->setUniformRowHeights(true);
    layers_->setMinimumWidth(320);
    bytes_ = new QPlainTextEdit{splitter};
    bytes_->setObjectName("packetBytes");
    bytes_->setReadOnly(true);
    bytes_->setUndoRedoEnabled(false);
    bytes_->setLineWrapMode(QPlainTextEdit::NoWrap);
    bytes_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    bytes_->setPlaceholderText("Select a packet to inspect its bytes.");
    splitter->setStretchFactor(0, 1);
    splitter->setStretchFactor(1, 1);
    layout->addWidget(splitter);
    connect(layers_, &QTreeWidget::currentItemChanged, this,
        [this](QTreeWidgetItem* current, QTreeWidgetItem*) { highlight(current); });
}

void PacketDetails::clear()
{
    layers_->clear();
    bytes_->setExtraSelections({});
    bytes_->clear();
    hex_positions_.clear();
    ascii_positions_.clear();
}

void PacketDetails::show_packet(const Packet& packet)
{
    clear();
    const auto& frame_bytes = packet.frame.data;
    QString dump;
    hex_positions_.reserve(frame_bytes.size());
    ascii_positions_.reserve(frame_bytes.size());
    // Sixteen bytes per line, with absolute offsets and printable ASCII.
    for (std::size_t offset = 0U; offset < frame_bytes.size(); offset += 16U) {
        const auto count = std::min(std::size_t{16}, frame_bytes.size() - offset);
        dump += QString("%1  ").arg(static_cast<qulonglong>(offset), 8, 16, QLatin1Char{'0'});
        for (std::size_t column = 0U; column < 16U; ++column) {
            if (column == 8U) dump += ' ';
            if (column < count) {
                hex_positions_.push_back(static_cast<int>(dump.size()));
                dump += QString("%1 ").arg(frame_bytes[offset + column], 2, 16, QLatin1Char{'0'});
            } else {
                dump += "   ";
            }
        }
        dump += " |";
        for (std::size_t column = 0U; column < count; ++column) {
            ascii_positions_.push_back(static_cast<int>(dump.size()));
            const auto byte = frame_bytes[offset + column];
            dump += byte >= 32U && byte <= 126U ? QChar{byte} : QChar{'.'};
        }
        dump += "|\n";
    }
    bytes_->setPlainText(dump);

    auto* frame = new QTreeWidgetItem{layers_, QStringList{
        QString("Frame %1").arg(static_cast<qulonglong>(packet.frame.number)),
        QString("%1 bytes on interface, %2 captured")
            .arg(static_cast<qulonglong>(packet.frame.original_length))
            .arg(static_cast<qulonglong>(packet.frame.captured_length))}};
    set_range(frame, 0U, frame_bytes.size());
    add_field(frame, "Timestamp", packet_timestamp(packet.frame));
    add_field(frame, "Original length", QString::number(packet.frame.original_length));
    add_field(frame, "Captured length", QString::number(packet.frame.captured_length));
    if (packet.frame.truncated()) add_field(frame, "Capture", "Truncated");
    if (!packet.error.empty()) add_field(frame, "Decode error", QString::fromStdString(packet.error));
    for (const auto& layer : packet.layers) {
        auto* item = new QTreeWidgetItem{layers_, QStringList{
            QString::fromStdString(layer.name),
            QString("Offset %1, %2 bytes").arg(static_cast<qulonglong>(layer.offset))
                .arg(static_cast<qulonglong>(layer.length))}};
        set_range(item, layer.offset, layer.length);
        for (const auto& [name, value] : layer.fields) {
            add_field(item, QString::fromStdString(name), QString::fromStdString(value));
        }
    }
    layers_->expandItem(frame);
}

void PacketDetails::highlight(QTreeWidgetItem* item)
{
    // Display fields currently lack individual byte ranges. Selecting a field
    // therefore highlights its containing header, without inventing offsets.
    while (item && !item->data(0, offset_role).isValid()) item = item->parent();
    QList<QTextEdit::ExtraSelection> selections;
    if (!item) {
        bytes_->setExtraSelections(selections);
        return;
    }
    const auto offset = static_cast<std::size_t>(item->data(0, offset_role).toULongLong());
    const auto length = static_cast<std::size_t>(item->data(0, length_role).toULongLong());
    if (offset >= hex_positions_.size()) {
        bytes_->setExtraSelections(selections);
        return;
    }
    const auto end = offset + std::min(length, hex_positions_.size() - offset);
    const auto add_selection = [this, &selections](const int begin, const int finish) {
        QTextEdit::ExtraSelection selection;
        selection.cursor = QTextCursor{bytes_->document()};
        selection.cursor.setPosition(begin);
        selection.cursor.setPosition(finish, QTextCursor::KeepAnchor);
        selection.format.setBackground(palette().brush(QPalette::Highlight));
        selection.format.setForeground(palette().brush(QPalette::HighlightedText));
        selections.append(selection);
    };
    for (auto at = offset; at < end;) {
        const auto line_end = std::min(end, (at / 16U + 1U) * 16U);
        add_selection(hex_positions_[at], hex_positions_[line_end - 1U] + 2);
        add_selection(ascii_positions_[at], ascii_positions_[line_end - 1U] + 1);
        at = line_end;
    }
    bytes_->setExtraSelections(selections);
    QTextCursor cursor{bytes_->document()};
    cursor.setPosition(hex_positions_[offset]);
    bytes_->setTextCursor(cursor);
    bytes_->ensureCursorVisible();
}

} // namespace deep_wire
