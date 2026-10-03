#pragma once

#include "packet_decoder.hpp"

#include <QWidget>

#include <vector>

class QPlainTextEdit;
class QTreeWidget;
class QTreeWidgetItem;

namespace deep_wire {

// Shows one packet's metadata, decoded layers, and original bytes. Selecting
// a layer highlights that header in both hexadecimal and ASCII columns.
class PacketDetails : public QWidget {
public:
    explicit PacketDetails(QWidget* parent = nullptr);
    void show_packet(const Packet& packet);
    void clear();

private:
    void highlight(QTreeWidgetItem* item);

    QTreeWidget* layers_{};
    QPlainTextEdit* bytes_{};
    // Text positions are generated alongside the hex dump, not guessed from
    // protocol sizes. They remain valid until the next packet is displayed.
    std::vector<int> hex_positions_;
    std::vector<int> ascii_positions_;
};

} // namespace deep_wire
