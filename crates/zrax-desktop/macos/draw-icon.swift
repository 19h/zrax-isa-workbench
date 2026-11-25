// Draw the Workbench's chip and Z glyph into a 1024 px transparent PNG.
// Usage: swift draw-icon.swift AppIcon.png

import AppKit
import ImageIO
import UniformTypeIdentifiers

let side = 1024
let context = CGContext(
    data: nil, width: side, height: side, bitsPerComponent: 8, bytesPerRow: 0,
    space: CGColorSpace(name: CGColorSpace.sRGB)!,
    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
)!

func color(_ hex: UInt32, alpha: CGFloat = 1) -> CGColor {
    CGColor(
        srgbRed: CGFloat((hex >> 16) & 255) / 255,
        green: CGFloat((hex >> 8) & 255) / 255,
        blue: CGFloat(hex & 255) / 255,
        alpha: alpha
    )
}

func roundedRect(_ rect: CGRect, radius: CGFloat) -> CGPath {
    CGPath(roundedRect: rect, cornerWidth: radius, cornerHeight: radius, transform: nil)
}

func fill(_ path: CGPath, _ paint: CGColor) {
    context.setFillColor(paint)
    context.addPath(path)
    context.fillPath()
}

func stroke(_ path: CGPath, _ paint: CGColor, width: CGFloat) {
    context.setStrokeColor(paint)
    context.setLineWidth(width)
    context.addPath(path)
    context.strokePath()
}

let tileBounds = CGRect(x: 75, y: 75, width: 874, height: 874)
let tile = roundedRect(tileBounds, radius: 200)

context.saveGState()
context.setShadow(offset: CGSize(width: 0, height: -17), blur: 34, color: color(0x080706, alpha: 0.45))
fill(tile, color(0x12100E))
context.restoreGState()

context.saveGState()
context.addPath(tile)
context.clip()
let colors = [color(0x35242A), color(0x171215), color(0x100E10)] as CFArray
let background = CGGradient(colorsSpace: context.colorSpace, colors: colors, locations: [0, 0.52, 1])!
context.drawLinearGradient(
    background, start: CGPoint(x: 200, y: 925), end: CGPoint(x: 815, y: 95),
    options: [.drawsBeforeStartLocation, .drawsAfterEndLocation]
)
context.restoreGState()

let bevel = roundedRect(tileBounds.insetBy(dx: 4, dy: 4), radius: 196)
stroke(bevel, color(0xDDA7B8, alpha: 0.19), width: 8)

// Package contacts use the same spacing on each side of the die.
let pinCenters: [CGFloat] = [359, 436, 512, 588, 665]
for center in pinCenters {
    let pinColor = center == 512 ? color(0xF47EA7) : color(0x995370)
    for x in [CGFloat(202), 751] {
        fill(roundedRect(CGRect(x: x, y: center - 14, width: 71, height: 28), radius: 9), pinColor)
    }
    for y in [CGFloat(202), 751] {
        fill(roundedRect(CGRect(x: center - 14, y: y, width: 28, height: 71), radius: 9), pinColor)
    }
}

let dieBounds = CGRect(x: 261, y: 261, width: 502, height: 502)
let die = roundedRect(dieBounds, radius: 105)
fill(die, color(0x171215))
stroke(die, color(0xBE6385), width: 10)
stroke(roundedRect(dieBounds.insetBy(dx: 24, dy: 24), radius: 82), color(0x503141), width: 4)

let glyph = CGMutablePath()
glyph.move(to: CGPoint(x: 366, y: 658))
glyph.addLine(to: CGPoint(x: 655, y: 658))
glyph.addLine(to: CGPoint(x: 655, y: 600))
glyph.addLine(to: CGPoint(x: 472, y: 432))
glyph.addLine(to: CGPoint(x: 655, y: 432))
glyph.addLine(to: CGPoint(x: 655, y: 366))
glyph.addLine(to: CGPoint(x: 366, y: 366))
glyph.addLine(to: CGPoint(x: 366, y: 425))
glyph.addLine(to: CGPoint(x: 550, y: 591))
glyph.addLine(to: CGPoint(x: 366, y: 591))
glyph.closeSubpath()

context.saveGState()
context.setShadow(offset: .zero, blur: 29, color: color(0xFF3D8B, alpha: 0.42))
fill(glyph, color(0xFF3D8B))
context.restoreGState()
context.saveGState()
context.addPath(glyph)
context.clip()
let signalColors = [color(0xFF95B8), color(0xFF3D8B), color(0xE72D73)] as CFArray
let signal = CGGradient(colorsSpace: context.colorSpace, colors: signalColors, locations: [0, 0.43, 1])!
context.drawLinearGradient(signal, start: CGPoint(x: 496, y: 658), end: CGPoint(x: 496, y: 366), options: [])
context.restoreGState()

let output = URL(fileURLWithPath: CommandLine.arguments[1])
let destination = CGImageDestinationCreateWithURL(output as CFURL, UTType.png.identifier as CFString, 1, nil)!
CGImageDestinationAddImage(destination, context.makeImage()!, nil)
precondition(CGImageDestinationFinalize(destination), "Could not write the app icon")
