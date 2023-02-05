#!/opt/homebrew/bin/bb

(let [[f1 f2 max-rules-str] *command-line-args*
      pp #(doseq [ele %] (println ele))
      max-rules (Integer/parseInt max-rules-str)]
  (with-open [r (io/reader f1)
              r2 (io/reader f2)]
    (-> (let [initial-rules (reduce conj [] (line-seq r))
              initial-present (set initial-rules)]
          (loop [lines (reduce conj [] (line-seq r2))
                 line (first lines)
                 present initial-present
                 result initial-rules]
            (if (or (>= (count result) max-rules)
                    (nil? line))
              result 
              (recur (rest lines)
                     (first (rest lines))
                     (conj present line)
                     (if (present line)
                       result (conj result line))))))
        pp)))
