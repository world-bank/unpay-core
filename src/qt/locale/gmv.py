dirs = ["dash_bar.ts",
"dash_bg.ts",
"dash_ca.ts",
"dash_cmn.ts",
"dash_cs.ts",
"dash_da.ts",
"dash_de.ts",
"dash_el.ts",
"dash_en.ts",
"dash_eo.ts",
"dash_es.ts",
"dash_fi.ts",
"dash_fr.ts",
"dash_hu_HU.ts",
"dash_it.ts",
"dash_lv_LV.ts",
"dash_nb.ts",
"dash_nl.ts",
"dash_pl.ts",
"dash_pt.ts",
"dash_pt_BR.ts",
"dash_ru.ts",
"dash_sk.ts",
"dash_sv.ts",
"dash_tr.ts",
"dash_vi.ts",
"dash_zh_CN.ts",
"dash_zh_HK.ts",]


import os 


for d in dirs:
	os.system("git mv "+ d + " unpay"+d[4:])