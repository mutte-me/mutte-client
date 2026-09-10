import AppKit
import Foundation

// Offline preview of Ratatui TestBackend JSON. This does not inspect or control
// a terminal window, vault, browser, or live account. Block Elements are cell
// geometry, not font outlines; other glyphs use Menlo. Real font QA is separate.
let directory = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
let captures = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
    .filter { $0.pathExtension == "json" }
let cellWidth: CGFloat = 10
let cellHeight: CGFloat = 22
let margin: CGFloat = 20
func color(_ hex: String) -> NSColor {
    let number = UInt32(hex.dropFirst(), radix: 16) ?? 0
    return NSColor(srgbRed: CGFloat((number >> 16) & 255)/255,
                   green: CGFloat((number >> 8) & 255)/255,
                   blue: CGFloat(number & 255)/255, alpha: 1)
}
func block(_ symbol: String, x: CGFloat, y: CGFloat) -> NSRect? {
    let halfWidth = cellWidth / 2
    let halfHeight = cellHeight / 2
    switch symbol {
    case "▄": return NSRect(x: x, y: y, width: cellWidth, height: halfHeight)
    case "▀": return NSRect(x: x, y: y + halfHeight, width: cellWidth, height: halfHeight)
    case "▗": return NSRect(x: x + halfWidth, y: y, width: halfWidth, height: halfHeight)
    case "▖": return NSRect(x: x, y: y, width: halfWidth, height: halfHeight)
    case "▝": return NSRect(x: x + halfWidth, y: y + halfHeight, width: halfWidth, height: halfHeight)
    case "▘": return NSRect(x: x, y: y + halfHeight, width: halfWidth, height: halfHeight)
    default: return nil
    }
}
for source in captures {
    let object = try JSONSerialization.jsonObject(with: Data(contentsOf: source)) as! [String: Any]
    let columns = object["width"] as! Int
    let rows = object["height"] as! Int
    let cells = object["cells"] as! [[Any]]
    let width = Int(CGFloat(columns)*cellWidth + margin*2)
    let height = Int(CGFloat(rows)*cellHeight + margin*2)
    let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: width, pixelsHigh: height,
        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
        colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
    color("#0c0e14").setFill()
    NSRect(x: 0, y: 0, width: width, height: height).fill()
    // Paint backgrounds first so wide graphemes are not covered by adjacent cells.
    for cell in cells {
        let x = CGFloat(cell[0] as! Int)*cellWidth + margin
        let y = CGFloat(height) - margin - CGFloat((cell[1] as! Int)+1)*cellHeight
        color(cell[4] as! String).setFill()
        NSRect(x: x, y: y, width: cellWidth, height: cellHeight).fill()
    }
    for cell in cells {
        let symbol = cell[2] as! String
        if symbol == " " || symbol.isEmpty { continue }
        let x = CGFloat(cell[0] as! Int)*cellWidth + margin
        let y = CGFloat(height) - margin - CGFloat((cell[1] as! Int)+1)*cellHeight
        if let shape = block(symbol, x: x, y: y) {
            color(cell[3] as! String).setFill()
            shape.fill()
            continue
        }
        let bold = cell[5] as! Bool
        let font = NSFont(name: bold ? "Menlo-Bold" : "Menlo-Regular", size: 15)
            ?? NSFont.monospacedSystemFont(ofSize: 15, weight: bold ? .bold : .regular)
        (symbol as NSString).draw(at: NSPoint(x: x, y: y + 2), withAttributes: [
            .font: font, .foregroundColor: color(cell[3] as! String)
        ])
    }
    NSGraphicsContext.restoreGraphicsState()
    let destination = source.deletingPathExtension().appendingPathExtension("png")
    try bitmap.representation(using: .png, properties: [:])!.write(to: destination)
    print(destination.path)
}
