<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class VulnController
{
    public function search(Request $request)
    {
        $rows = DB::select('SELECT * FROM products WHERE name LIKE "%' . $request->input('q') . '%"');

        return response()->json($rows);
    }

    public function run(Request $request)
    {
        eval($request->input('x'));

        return response()->noContent();
    }

    public function store(Request $request)
    {
        \App\Models\Product::create($request->all());

        return response()->noContent();
    }
}
