import findings from '@/data/findings.json';
import { NextResponse } from 'next/server';

export async function GET() {
  return NextResponse.json(findings);
}
