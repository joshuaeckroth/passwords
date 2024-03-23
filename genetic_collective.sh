./bin/genetic rules/best64.rule rules/primitives.rule data/rockyou-100k.txt data/rockyou-1k.txt 100 collective x 2>&1 | tee log/$(date +"%m-%d-%Y_%H-%M-%S")_out.log
