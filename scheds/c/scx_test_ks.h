struct time_datum {
	u64 time_start;
	u64 time_end;
	u64 elapsed_ns;
};

struct struct_data {
	struct time_datum td;
	int data;
};