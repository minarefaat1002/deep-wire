#pragma once

#include "packet_decoder.hpp"

#include <QAbstractTableModel>
#include <QString>

#include <vector>

namespace deep_wire {

// Owns retained packets and exposes their summary columns. All methods run
// on the GUI thread; capture hands packets over through CaptureSession.
class PacketTableModel : public QAbstractTableModel {
public:
    explicit PacketTableModel(QObject* parent = nullptr);

    int rowCount(const QModelIndex& parent = {}) const override;
    int columnCount(const QModelIndex& parent = {}) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation,
        int role = Qt::DisplayRole) const override;

    void append(std::vector<Packet> packets);
    void clear();
    [[nodiscard]] const Packet* packet_at(int row) const;

private:
    std::vector<Packet> packets_;
};

// Full UTC capture time with the kernel's nanosecond fraction.
[[nodiscard]] QString packet_timestamp(const CapturedFrame& frame);

} // namespace deep_wire
