#include "main_window.hpp"

#include <QApplication>

int main(int argc, char* argv[])
{
    QApplication app{argc, argv};
    QApplication::setApplicationName("Deep Wire");
    QApplication::setApplicationVersion("0.1.0");
    deep_wire::MainWindow window;
    window.show();
    return app.exec();
}
