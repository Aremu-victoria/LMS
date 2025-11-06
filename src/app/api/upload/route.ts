import { NextRequest, NextResponse } from 'next/server';
import formidable, { File } from 'formidable';
import fs from 'fs';
import path from 'path';
import type { IncomingMessage } from 'http';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest): Promise<NextResponse> {
	const uploadDir = path.join(process.cwd(), 'public', 'uploads');
	await fs.promises.mkdir(uploadDir, { recursive: true });

	const form = formidable({
		uploadDir,
		keepExtensions: true,
		multiples: true,
	});

	// Fallback to Node stream parsing when running in Node environment
	const files: Array<{ filename: string; filepath: string; mimetype: string; size: number }> = [];

		return new Promise<NextResponse>((resolve) => {
	form.parse(req as unknown as IncomingMessage, (err, _fields, formFiles) => {
			if (err) {
				resolve(NextResponse.json({ error: 'Upload failed' }, { status: 400 }));
				return;
			}
			const flat = Object.values(formFiles).flat() as File[];
			for (const f of flat) {
				files.push({
					filename: f.originalFilename || path.basename(f.filepath),
					filepath: `/uploads/${path.basename(f.filepath)}`,
					mimetype: f.mimetype || 'application/octet-stream',
					size: f.size,
				});
			}
			resolve(NextResponse.json({ files }));
		});
	});
}








